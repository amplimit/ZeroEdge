use crate::dht::PublicDht;
use crate::network::NetworkManager;
use crate::identity::UserIdentity;

use colored::*;
use rustyline::error::ReadlineError;
use rustyline::{DefaultEditor, Result as RustylineResult};
use rustyline::completion::{Completer, Pair};
use rustyline::hint::{Hinter, HistoryHinter};
use rustyline::validate::Validator;
use rustyline::highlight::{Highlighter, MatchingBracketHighlighter};
use rustyline::Context;
use shlex::split;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use log::error;
use super::commands::{Command, CommandResult, CommandContext};

/// 命令补全器
#[derive(Default)]
struct CommandCompleter {
    commands: Vec<String>,
}

impl Completer for CommandCompleter {
    type Candidate = Pair;

    fn complete(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> rustyline::Result<(usize, Vec<Pair>)> {
        let mut candidates = Vec::new();
        
        // 只有在命令开头时才提供补全
        if line.starts_with('/') {
            let word = &line[1..pos];
            for cmd in &self.commands {
                if cmd.starts_with(word) {
                    candidates.push(Pair {
                        display: format!("/{}", cmd),
                        replacement: cmd.clone(),
                    });
                }
            }
            return Ok((1, candidates));
        }
        
        Ok((pos, candidates))
    }
}

/// 命令行编辑器配置
struct EditorConfig {
    completer: CommandCompleter,
    highlighter: MatchingBracketHighlighter,
    hinter: HistoryHinter,
}

impl Validator for EditorConfig {}

impl Hinter for EditorConfig {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &Context<'_>) -> Option<String> {
        self.hinter.hint(line, pos, ctx)
    }
}

impl Highlighter for EditorConfig {
    fn highlight<'l>(&self, line: &'l str, pos: usize) -> Cow<'l, str> {
        self.highlighter.highlight(line, pos)
    }

    fn highlight_char(&self, line: &str, pos: usize) -> bool {
        self.highlighter.highlight_char(line, pos)
    }
}

impl Completer for EditorConfig {
    type Candidate = Pair;

    fn complete(&self, line: &str, pos: usize, ctx: &Context<'_>) -> rustyline::Result<(usize, Vec<Pair>)> {
        self.completer.complete(line, pos, ctx)
    }
}

/// 命令处理器
pub struct CommandProcessor {
    dht: Arc<PublicDht>,
    network: Arc<NetworkManager>,
    identity: Arc<UserIdentity>,
    commands: HashMap<String, Command>,
    running: Arc<Mutex<bool>>,
    command_tx: mpsc::Sender<String>,
    result_rx: mpsc::Receiver<CommandResult>,
}

impl CommandProcessor {
    /// 创建新的命令处理器
    pub fn new(
        dht: PublicDht,
        network: NetworkManager,
        identity: UserIdentity,
    ) -> (Self, mpsc::Receiver<String>, mpsc::Sender<CommandResult>) {
        let (command_tx, command_rx) = mpsc::channel(100);
        let (result_tx, result_rx) = mpsc::channel(100);
        
        let dht = Arc::new(dht);
        let network = Arc::new(network);
        let identity = Arc::new(identity);
        let running = Arc::new(Mutex::new(true));
        
        let mut commands = HashMap::new();
        
        // 注册命令
        commands.insert("help".to_string(), Command::Help);
        commands.insert("exit".to_string(), Command::Exit);
        commands.insert("quit".to_string(), Command::Exit);
        commands.insert("send".to_string(), Command::Send);
        commands.insert("contacts".to_string(), Command::Contacts);
        commands.insert("create-group".to_string(), Command::CreateGroup);
        commands.insert("add-to-group".to_string(), Command::AddToGroup);
        commands.insert("find".to_string(), Command::Find);
        commands.insert("whoami".to_string(), Command::WhoAmI);
        commands.insert("status".to_string(), Command::Status);
        commands.insert("dht-routes".to_string(), Command::DhtRoutes);
        
        (
            Self {
                dht,
                network,
                identity,
                commands,
                running,
                command_tx,
                result_rx,
            },
            command_rx,
            result_tx,
        )
    }
    
    /// 启动命令处理器
    pub async fn start(&mut self) -> anyhow::Result<()> {
        // 显示欢迎信息
        println!("{}", self.get_welcome_message());
        
        // 创建编辑器
        let mut editor = self.create_editor()?;
        
        // 命令行循环
        while *self.running.lock().await {
            // 处理命令结果
            if let Ok(result) = self.result_rx.try_recv() {
                self.handle_command_result(result).await;
            }
            
            // 读取用户输入
            let prompt = format!("{} ", "zero_edge>".green().bold());
            match editor.readline(&prompt) {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    
                    // 添加到历史记录
                    editor.add_history_entry(line)?;
                    
                    // 处理命令
                    if let Err(e) = self.process_input(line).await {
                        eprintln!("{} {}", "Error:".red().bold(), e);
                    }
                },
                Err(ReadlineError::Interrupted) => {
                    println!("CTRL-C");
                    break;
                },
                Err(ReadlineError::Eof) => {
                    println!("CTRL-D");
                    break;
                },
                Err(err) => {
                    error!("Error reading line: {}", err);
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    /// 创建命令行编辑器
    fn create_editor(&self) -> RustylineResult<DefaultEditor> {
        let mut editor = DefaultEditor::new()?;
        
        // 加载历史记录
        let _ = editor.load_history("history.txt");
        
        // 设置自动补全
        let commands: Vec<String> = self.commands.keys().cloned().collect();
        let _config = EditorConfig {
            completer: CommandCompleter { commands },
            highlighter: MatchingBracketHighlighter::new(),
            hinter: HistoryHinter {},
        };
        
        // 设置编辑器配置
        // 暂时注释掉，需要适配rustyline版本
        // editor.set_helper(Some(config));
        
        Ok(editor)
    }
    
    /// 处理用户输入
    async fn process_input(&self, input: &str) -> anyhow::Result<()> {
        // 解析命令
        let (cmd, args) = self.parse_command(input)?;
        
        // 执行命令
        self.execute_command(cmd, args).await
    }
    
    /// 解析命令
    fn parse_command(&self, input: &str) -> anyhow::Result<(String, Vec<String>)> {
        // 检查是否是命令
        let input = input.trim();
        let (cmd, args_str) = if input.starts_with('/') {
            // 去掉前导斜杠
            let parts: Vec<&str> = input[1..].splitn(2, ' ').collect();
            if parts.is_empty() {
                return Err(anyhow::anyhow!("Empty command"));
            }
            
            (parts[0].to_string(), parts.get(1).unwrap_or(&"").to_string())
        } else {
            // 默认为发送消息
            ("send".to_string(), input.to_string())
        };
        
        // 解析参数
        let args = match split(&args_str) {
            Some(args) => args,
            None => return Err(anyhow::anyhow!("Invalid command arguments")),
        };
        
        Ok((cmd, args))
    }
    
    /// 执行命令
    async fn execute_command(&self, cmd: String, args: Vec<String>) -> anyhow::Result<()> {
        // 查找命令
        let command = match self.commands.get(&cmd) {
            Some(command) => command.clone(),
            None => {
                return Err(anyhow::anyhow!("Unknown command: {}", cmd));
            }
        };
        
        // 创建命令上下文
        let context = CommandContext {
            dht: self.dht.clone(),
            network: self.network.clone(),
            identity: self.identity.clone(),
            args,
        };
        
        // 发送命令到处理线程
        self.command_tx.send(format!("{:?} {:?}", command, context)).await?;
        
        Ok(())
    }
    
    /// 处理命令结果
    async fn handle_command_result(&self, result: CommandResult) -> anyhow::Result<()> {
        match result {
            CommandResult::Success(message) => {
                println!("{}", message.green());
            },
            CommandResult::Info(message) => {
                println!("{}", message);
            },
            CommandResult::Warning(message) => {
                println!("{}", message.yellow());
            },
            CommandResult::Error(message) => {
                println!("{}", message.red());
            },
            CommandResult::Exit => {
                *self.running.lock().await = false;
            },
        }
        
        Ok(())
    }
    
    /// 获取欢迎信息
    /// 获取欢迎信息
    fn get_welcome_message(&self) -> String {
        let version = env!("CARGO_PKG_VERSION");
        
        format!(
            "\n{}\n{}\n\nType {} for a list of available commands.\n\nYour Identity:\n  User ID: {}\n", 
            format!("ZeroEdge v{}", version).green().bold(),
            "A fully decentralized P2P chat protocol".cyan(),
            "/help".yellow(),
            self.identity.id.to_string().green()
        )
    }
    
    /// 停止命令处理器
    pub async fn stop(&self) -> anyhow::Result<()> {
        // 保存历史记录
        let mut editor = self.create_editor()?;
        let _ = editor.save_history("history.txt");
        
        // 设置运行标志为false
        *self.running.lock().await = false;
        
        Ok(())
    }
}
