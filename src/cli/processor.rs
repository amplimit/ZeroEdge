use crate::dht::PublicDht;
use crate::network::NetworkManager;
use crate::identity::UserIdentity;

use colored::*;
use rustyline::{DefaultEditor, Result as RustylineResult, error::ReadlineError};
// Removed: use rustyline::validate::MatchingBracketValidator;
use rustyline::hint::HistoryHinter;
use rustyline::highlight::MatchingBracketHighlighter;
use rustyline::completion::{Completer, Pair};
use rustyline::validate::Validator;
use rustyline::hint::Hinter;
use rustyline::highlight::Highlighter;
use rustyline::Context;
use rustyline::config::Configurer;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use log::{error, debug};
use super::commands::{Command, CommandResult, CommandContext};
use clap::{Command as ClapCommand, Arg, ArgMatches};
use anyhow::{Result, anyhow};
use std::path::PathBuf;
use std::fs::create_dir_all;

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
                        display: format!("/{}", cmd.as_str()),
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

/// 创建clap应用程序，定义所有可用的命令和参数
fn create_cli_app() -> ClapCommand {
    ClapCommand::new("ZeroEdge CLI")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about("ZeroEdge P2P Chat System Command Line Interface")
        .no_binary_name(true)
        .subcommand(ClapCommand::new("help")
            .about("显示帮助信息"))
        .subcommand(ClapCommand::new("exit")
            .about("退出应用程序"))
        .subcommand(ClapCommand::new("quit")
            .about("退出应用程序"))
        .subcommand(ClapCommand::new("send")
            .about("发送消息给指定节点")
            .arg(Arg::new("node_id")
                .help("接收者的节点ID")
                .required(true)
                .index(1))
            .arg(Arg::new("message")
                .help("要发送的消息内容")
                .required(true)
                .num_args(1..)
                .index(2)))
        .subcommand(ClapCommand::new("contacts")
            .about("列出所有联系人"))
        .subcommand(ClapCommand::new("create-group")
            .about("创建新的群组")
            .arg(Arg::new("name")
                .help("群组名称")
                .required(true)
                .index(1)))
        .subcommand(ClapCommand::new("add-to-group")
            .about("添加联系人到群组")
            .arg(Arg::new("group_id")
                .help("群组ID")
                .required(true)
                .index(1))
            .arg(Arg::new("node_id")
                .help("要添加的节点ID")
                .required(true)
                .index(2)))
        .subcommand(ClapCommand::new("find")
            .about("在DHT中查找节点")
            .arg(Arg::new("node_id")
                .help("要查找的节点ID")
                .required(true)
                .index(1)))
        .subcommand(ClapCommand::new("whoami")
            .about("显示当前身份信息"))
        .subcommand(ClapCommand::new("status")
            .about("显示网络状态"))
        .subcommand(ClapCommand::new("dht-routes")
            .about("显示DHT路由表"))
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
    history_path: PathBuf,
}

impl CommandProcessor {
    /// 创建新的命令处理器
    pub fn new(
        dht: Arc<PublicDht>,
        network: Arc<NetworkManager>,
        identity: Arc<UserIdentity>,
    ) -> (Self, mpsc::Receiver<String>, mpsc::Sender<CommandResult>) {
        let (command_tx, command_rx) = mpsc::channel(100);
        let (result_tx, result_rx) = mpsc::channel(100);
        
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
        
        // 设置历史记录文件路径
        let mut history_path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        history_path.push("zeroedge");
        history_path.push("history.txt");
        
        // 确保目录存在
        if let Some(parent) = history_path.parent() {
            let _ = create_dir_all(parent);
        }
        
        (
            Self {
                dht,
                network,
                identity,
                commands,
                running,
                command_tx,
                result_rx,
                history_path,
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
        
        // 创建CLI应用
        let app = create_cli_app();
        
        // 命令行循环
        while *self.running.lock().await {
            // 处理命令结果
            if let Ok(result) = self.result_rx.try_recv() {
                self.handle_command_result(result).await?;
            }
            
            // 读取用户输入
            print!("{} ", "zero_edge>".green());
            match editor.readline("") {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    
                    // 添加到历史记录
                    editor.add_history_entry(line)?;
                    
                    // 保存历史记录
                    if let Err(e) = editor.save_history(&self.history_path) {
                        debug!("Failed to save command history: {}", e);
                    }
                    
                    // 处理命令 - 使用新的基于clap的命令处理
                    if let Err(e) = self.process_command_with_clap(line, &app).await {
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
        let _ = editor.load_history(&self.history_path);
        
        // 设置自动补全
        let commands: Vec<String> = self.commands.keys().cloned().collect();
        let _config = EditorConfig { // Prefixed with underscore
            completer: CommandCompleter { commands },
            highlighter: MatchingBracketHighlighter::new(),
            hinter: HistoryHinter {},
        };
        
        // 设置编辑器配置
        editor.set_auto_add_history(true);
        editor.set_edit_mode(rustyline::EditMode::Emacs);
        editor.set_color_mode(rustyline::ColorMode::Enabled);
        
        Ok(editor)
    }
    
    /// 使用clap处理命令
    async fn process_command_with_clap(&self, input: &str, app: &ClapCommand) -> Result<()> {
        // 去掉前后空格
        let input = input.trim();
        
        // 检查是否是以/开头的命令
        let cmd_str = if input.starts_with('/') {
            // 去掉开头的/
            &input[1..]
        } else {
            // 如果不是以/开头，但是一个有效的命令
            if self.commands.contains_key(input.split_whitespace().next().unwrap_or("")) {
                // 直接将输入视为命令
                input
            } else {
                // 如果不是已知命令，则还是当作消息处理
                // 检查是否有当前活跃会话或使用默认联系人
                return Err(anyhow!("Not implemented: Direct message sending without active session"));
            }
        };
        
        // 使用clap解析命令
        let args: Vec<&str> = cmd_str.split_whitespace().collect();
        let matches = match app.clone().try_get_matches_from(args) {
            Ok(matches) => matches,
            Err(e) => {
                // 如果解析失败，显示错误信息
                return Err(anyhow!("Command parsing error: {}", e));
            }
        };
        
        // 处理子命令
        if let Some((cmd_name, sub_matches)) = matches.subcommand() {
            self.handle_subcommand(cmd_name, sub_matches).await
        } else {
            // 如果没有子命令，显示帮助信息
            self.execute_command_with_context("help", vec![]).await
        }
    }
    
    /// 处理子命令
    async fn handle_subcommand(&self, cmd_name: &str, matches: &ArgMatches) -> Result<()> {
        match cmd_name {
            "help" => self.execute_command_with_context("help", vec![]).await,
            "exit" | "quit" => self.execute_command_with_context("exit", vec![]).await,
            "send" => {
                let node_id = matches.get_one::<String>("node_id").unwrap().to_string();
                let message = matches.get_many::<String>("message")
                    .map(|vals| vals.map(|s| s.to_string()).collect::<Vec<_>>().join(" "))
                    .unwrap_or_default();
                self.execute_command_with_context("send", vec![node_id, message]).await
            },
            "contacts" => self.execute_command_with_context("contacts", vec![]).await,
            "create-group" => {
                let name = matches.get_one::<String>("name").unwrap().to_string();
                self.execute_command_with_context("create-group", vec![name]).await
            },
            "add-to-group" => {
                let group_id = matches.get_one::<String>("group_id").unwrap().to_string();
                let node_id = matches.get_one::<String>("node_id").unwrap().to_string();
                self.execute_command_with_context("add-to-group", vec![group_id, node_id]).await
            },
            "find" => {
                let node_id = matches.get_one::<String>("node_id").unwrap().to_string();
                self.execute_command_with_context("find", vec![node_id]).await
            },
            "whoami" => self.execute_command_with_context("whoami", vec![]).await,
            "status" => self.execute_command_with_context("status", vec![]).await,
            "dht-routes" => self.execute_command_with_context("dht-routes", vec![]).await,
            _ => Err(anyhow!("Unknown command: {}", cmd_name))
        }
    }
    
    /// 执行命令
    async fn execute_command_with_context(&self, cmd: &str, args: Vec<String>) -> Result<()> {
        // 查找命令
        let command = self.commands.get(cmd)
            .ok_or_else(|| anyhow!("Unknown command: {}", cmd))?;
        
        // 创建命令上下文
        let context = CommandContext {
            dht: self.dht.clone(),
            network: self.network.clone(),
            identity: self.identity.clone(),
            args,
        };
        
        // 执行命令
        let result = command.execute(context).await;
        
        // 处理命令执行结果
        match result {
            CommandResult::Success(message) => {
                if !message.is_empty() {
                    println!("{}", message);
                }
            },
            CommandResult::Error(error) => {
                eprintln!("{} {}", "Error:".red().bold(), error);
            },
            CommandResult::Info(info) => {
                println!("{}", info);
            },
            CommandResult::Warning(warning) => {
                println!("{} {}", "Warning:".yellow().bold(), warning);
            },
            CommandResult::Exit => {
                // Exit命令将在外层处理
            }
        }
        
        // 发送通知
        let _ = self.command_tx.send(format!("Command::{:?}", command)).await
            .map_err(|e| anyhow!("Failed to send command: {}", e))?;
        
        Ok(())
    }
    
    /// 处理命令结果
    async fn handle_command_result(&self, result: CommandResult) -> Result<()> {
        match result {
            CommandResult::Success(message) => {
                println!("{} {}", "Success:".green().bold(), message);
            },
            CommandResult::Info(message) => {
                println!("{}", message);
            },
            CommandResult::Warning(message) => {
                println!("{} {}", "Warning:".yellow().bold(), message);
            },
            CommandResult::Error(message) => {
                println!("{} {}", "Error:".red().bold(), message);
            },
            CommandResult::Exit => {
                println!("Exiting...");
                let mut running = self.running.lock().await;
                *running = false;
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
