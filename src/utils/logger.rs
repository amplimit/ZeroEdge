use log::LevelFilter;
use env_logger::{Builder, Env};

/// 设置日志记录器
pub fn setup_logger(level: Option<LevelFilter>) -> Result<(), String> {
    // 从环境变量获取日志级别
    let env = Env::default().default_filter_or(level_to_string(level.unwrap_or(LevelFilter::Info)));
    
    // 创建日志构建器
    let mut builder = Builder::from_env(env);
    
    // 初始化日志
    builder.init();
    
    Ok(())
}

/// 将日志级别转换为字符串
fn level_to_string(level: LevelFilter) -> &'static str {
    match level {
        LevelFilter::Off => "off",
        LevelFilter::Error => "error",
        LevelFilter::Warn => "warn",
        LevelFilter::Info => "info",
        LevelFilter::Debug => "debug",
        LevelFilter::Trace => "trace",
    }
}

/// 从字符串解析日志级别
pub fn parse_log_level(level_str: &str) -> Result<LevelFilter, String> {
    match level_str.to_lowercase().as_str() {
        "off" => Ok(LevelFilter::Off),
        "error" => Ok(LevelFilter::Error),
        "warn" => Ok(LevelFilter::Warn),
        "info" => Ok(LevelFilter::Info),
        "debug" => Ok(LevelFilter::Debug),
        "trace" => Ok(LevelFilter::Trace),
        _ => Err(format!("Invalid log level: {}", level_str)),
    }
}
