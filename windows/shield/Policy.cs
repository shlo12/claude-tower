using System;
namespace CCShieldWindows {
sealed class Snapshot {
 public DateTime At=DateTime.UtcNow;
 public bool Controller,Proxy,Tun,V6,ConnectionsKnown,Direct,Certificate,Conflict;
 public bool Transport,Dns,EdgeComplete;
 public string Node="",Route="",Exit="",Udp="",Timezone=TimeZoneInfo.Local.Id,DiscoveryPath="",DiscoveryLaunch="";
 public string Error="";
 public string Critical() {
  if(!Controller||Node=="")return "节点或全局模式未确认";
  if(!Proxy)return "系统代理未指向当前客户端";
  if(!Tun)return "未确认当前 IPv4 路由由受支持 TUN 接管";
  if(!V6)return "IPv6 接管或无默认路由状态未确认";
  if(!ConnectionsKnown)return "实际 TCP 路由采样未完成";
  if(Direct)return "发现 Claude TCP 连接未走当前 TUN";
  if(Certificate)return "HTTPS 证书验证失败";
  if(Conflict)return "Claude 域名出口不一致";
  return "";
 }
 public string Issue() { var hard=Critical();if(hard!="")return hard;if(!Dns)return "DNS 解析尚未完成";if(!Transport)return "HTTPS 传输尚未通过";if(!EdgeComplete||Exit=="")return "Claude 边缘出口未完整取得";if(Udp=="")return "UDP 出口未取得，不能确认 UDP 路径";if(Udp!=Exit)return "UDP 与 HTTPS 实测出口不一致";return ""; }
 public string Binding() {return Node+"|"+Route+"|"+Timezone+"|"+Exit;}
}
sealed class Decision { public bool Stop,Retry;public string Note=""; }
sealed class SessionPolicy {
 public string Admission="";public DateTime Issued;DateTime? retrySince;
 public void Reset(){Admission="";retrySince=null;}
 public Decision Evaluate(Snapshot s,DateTime now) {
  string hard=s.Critical();if(hard!="")return new Decision{Stop=true,Note=hard};
  if(Admission=="")return new Decision{Stop=true,Note="本次启动未获准入，请使用检查后启动"};
  if(now-s.At>TimeSpan.FromSeconds(45))return new Decision{Stop=true,Note="关键路由证据已过期"};
  if(now<s.At||now<Issued)return new Decision{Stop=true,Note="系统时间变化，需重新检查"};
  string prefix=s.Node+"|"+s.Route+"|"+s.Timezone+"|";
  if(!Admission.StartsWith(prefix,StringComparison.Ordinal))return new Decision{Stop=true,Note="节点、路由或时区已变化"};
  string approved=Admission.Substring(prefix.Length);
  if(s.Exit!=""&&s.Exit!=approved)return new Decision{Stop=true,Note="实际 HTTPS 出口已变化"};
  if(s.Udp!=""&&s.Udp!=approved)return new Decision{Stop=true,Note="UDP 出口与准入不一致"};
  if(s.Issue()==""){retrySince=null;return new Decision{Note="戒严值守中"};}
  if(!retrySince.HasValue)retrySince=now;
  if(now-retrySince.Value>=TimeSpan.FromSeconds(120))return new Decision{Stop=true,Note="辅助网络探测连续 120 秒未恢复"};
  return new Decision{Retry=true,Note="接管与节点仍在位；辅助网络探测波动，最长 120 秒复测"};
 }
}
}
