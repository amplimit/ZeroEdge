use crate::message::Message;
use colored::*;
use chrono::{DateTime, Utc, TimeZone};
use std::time::{Duration, UNIX_EPOCH};
use std::str;


/// 格式化消息显示
pub fn format_message(message: &Message, is_outgoing: bool) -> String {
    // 转换时间戳
    let timestamp = UNIX_EPOCH + Duration::from_secs(message.timestamp);
    let timestamp_secs = timestamp.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let datetime: DateTime<Utc> = Utc.timestamp_opt(timestamp_secs, 0).unwrap();
    let time_str = datetime.format("%H:%M:%S").to_string();
    
    // 确定消息前缀和颜色
    let prefix = if is_outgoing { ">>>" } else { "<<<" };
    let content_color = if is_outgoing { "cyan" } else { "green" };
    
    // 尝试将内容转换为字符串
    let content_str = match str::from_utf8(&message.content) {
        Ok(s) => s,
        Err(_) => "[Binary content]"
    };
    
    // 格式化消息内容
    format!(
        "{} {} [{}]: {}", 
        prefix.bold(),
        message.sender_id.to_string()[..8].yellow(),
        time_str.dimmed(),
        colorize(content_str, content_color)
    )
}

/// 根据指定颜色为文本着色
fn colorize(text: &str, color: &str) -> ColoredString {
    match color {
        "red" => text.red(),
        "green" => text.green(),
        "yellow" => text.yellow(),
        "blue" => text.blue(),
        "magenta" => text.magenta(),
        "cyan" => text.cyan(),
        "white" => text.white(),
        _ => text.normal(),
    }
}

/// 格式化进度条
pub fn format_progress_bar(progress: f32, width: usize) -> String {
    let progress = progress.clamp(0.0, 1.0);
    let filled_width = (progress * width as f32) as usize;
    let empty_width = width - filled_width;
    
    let filled = "=".repeat(filled_width);
    let empty = " ".repeat(empty_width);
    
    format!("[{}{}] {:.1}%", filled.green(), empty, progress * 100.0)
}

/// 格式化表格
pub fn format_table(headers: &[&str], rows: &[Vec<String>], widths: &[usize]) -> String {
    let mut result = String::new();
    
    // 添加表头
    let header_row = headers.iter()
        .zip(widths.iter())
        .map(|(h, w)| format!("{:width$}", h.bold(), width = *w))
        .collect::<Vec<_>>()
        .join(" | ");
    
    result.push_str(&header_row);
    result.push('\n');
    
    // 添加分隔线
    let separator = widths.iter()
        .map(|w| "-".repeat(*w))
        .collect::<Vec<_>>()
        .join("-+-");
    
    result.push_str(&separator);
    result.push('\n');
    
    // 添加数据行
    for row in rows {
        let data_row = row.iter()
            .zip(widths.iter())
            .map(|(cell, w)| format!("{:width$}", cell, width = *w))
            .collect::<Vec<_>>()
            .join(" | ");
        
        result.push_str(&data_row);
        result.push('\n');
    }
    
    result
}

/// 格式化字节大小
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    format!("{:.2} {}", size, UNITS[unit_index])
}

/// 格式化持续时间
pub fn format_duration(seconds: u64) -> String {
    let days = seconds / (24 * 3600);
    let hours = (seconds % (24 * 3600)) / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;
    
    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, seconds)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}
