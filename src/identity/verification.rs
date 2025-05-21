use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Invalid verification method: {0}")]
    InvalidMethod(String),
}

/// 用户身份验证方法
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum VerificationMethod {
    /// 通过扫描二维码进行验证
    QrCode(String),
    
    /// 通过比较验证码进行验证
    VerificationCode(String),
    
    /// 通过社交媒体验证
    SocialMedia {
        platform: String,
        username: String,
        proof: String,
    },
    
    /// 通过面对面验证
    InPerson,
    
    /// 通过信任网络间接验证
    WebOfTrust {
        path: Vec<String>,
        trust_level: f32,
    },
}

/// 验证状态
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// 未验证
    NotVerified,
    
    /// 正在进行验证
    Pending {
        method: VerificationMethod,
        started_at: u64,
    },
    
    /// 验证完成
    Verified {
        method: VerificationMethod,
        timestamp: u64,
    },
    
    /// 验证失败
    Failed {
        method: VerificationMethod,
        reason: String,
        timestamp: u64,
    },
}

impl VerificationStatus {
    /// 检查身份是否已经验证
    pub fn is_verified(&self) -> bool {
        matches!(self, VerificationStatus::Verified { .. })
    }
    
    /// 获取验证时间戳
    pub fn timestamp(&self) -> Option<u64> {
        match self {
            VerificationStatus::Verified { timestamp, .. } => Some(*timestamp),
            VerificationStatus::Failed { timestamp, .. } => Some(*timestamp),
            _ => None,
        }
    }
    
    /// 获取使用的验证方法
    pub fn method(&self) -> Option<&VerificationMethod> {
        match self {
            VerificationStatus::Pending { method, .. } => Some(method),
            VerificationStatus::Verified { method, .. } => Some(method),
            VerificationStatus::Failed { method, .. } => Some(method),
            _ => None,
        }
    }
}

/// 验证用户身份
pub fn verify_identity(
    method: VerificationMethod,
    proof: &str,
) -> Result<VerificationStatus, VerificationError> {
    // 在实际实现中，这里会执行真正的验证逻辑
    // 这里只是一个简化的示例
    
    // 获取当前时间戳
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    
    // 根据验证方法执行不同的验证逻辑
    match &method {
        VerificationMethod::QrCode(code) => {
            if code == proof {
                Ok(VerificationStatus::Verified {
                    method,
                    timestamp: now,
                })
            } else {
                Ok(VerificationStatus::Failed {
                    method,
                    reason: "QR码不匹配".to_string(),
                    timestamp: now,
                })
            }
        },
        VerificationMethod::VerificationCode(expected) => {
            if expected == proof {
                Ok(VerificationStatus::Verified {
                    method,
                    timestamp: now,
                })
            } else {
                Ok(VerificationStatus::Failed {
                    method,
                    reason: "验证码不匹配".to_string(),
                    timestamp: now,
                })
            }
        },
        VerificationMethod::SocialMedia { .. } => {
            // 简化实现，假设验证成功
            Ok(VerificationStatus::Verified {
                method,
                timestamp: now,
            })
        },
        VerificationMethod::InPerson => {
            Ok(VerificationStatus::Verified {
                method,
                timestamp: now,
            })
        },
        VerificationMethod::WebOfTrust { trust_level, .. } => {
            if *trust_level >= 0.7 {
                Ok(VerificationStatus::Verified {
                    method,
                    timestamp: now,
                })
            } else {
                Ok(VerificationStatus::Failed {
                    method,
                    reason: "信任级别不足".to_string(),
                    timestamp: now,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_code() {
        let method = VerificationMethod::VerificationCode("123456".to_string());
        
        // 正确的验证码
        let result = verify_identity(method.clone(), "123456");
        assert!(matches!(result, Ok(VerificationStatus::Verified { .. })));
        
        // 错误的验证码
        let result = verify_identity(method, "654321");
        assert!(matches!(result, Ok(VerificationStatus::Failed { .. })));
    }
    
    #[test]
    fn test_is_verified() {
        let status = VerificationStatus::Verified {
            method: VerificationMethod::InPerson,
            timestamp: 123456789,
        };
        
        assert!(status.is_verified());
        
        let status = VerificationStatus::Failed {
            method: VerificationMethod::InPerson,
            reason: "测试失败".to_string(),
            timestamp: 123456789,
        };
        
        assert!(!status.is_verified());
    }
}
