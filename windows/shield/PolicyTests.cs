using System;
namespace CCShieldWindows {
static class PolicyTests {
 static int count;
 static void Check(bool value,string name){count++;if(!value)throw new Exception("Policy test failed: "+name);}
 static Snapshot Ready(DateTime at){return new Snapshot{At=at,Controller=true,Proxy=true,Tun=true,V6=true,ConnectionsKnown=true,Transport=true,Dns=true,EdgeComplete=true,Node="node",Route="tun",Exit="203.0.113.4",Udp="203.0.113.4"};}
 internal static int Run(){count=0;var now=DateTime.UtcNow;var p=new SessionPolicy();var good=Ready(now);p.Admission=good.Binding();p.Issued=now;
 Check(good.Issue()=="","admission ready");Check(!p.Evaluate(good,now).Stop,"healthy");
 foreach(string field in new[]{"Controller","Proxy","Tun","V6","ConnectionsKnown"}){var s=Ready(now);typeof(Snapshot).GetField(field).SetValue(s,false);Check(s.Issue()!=""&&p.Evaluate(s,now).Stop,"missing "+field);}
 foreach(string field in new[]{"Direct","Certificate","Conflict"}){var s=Ready(now);typeof(Snapshot).GetField(field).SetValue(s,true);Check(s.Issue()!=""&&p.Evaluate(s,now).Stop,"critical "+field);}
 foreach(string field in new[]{"Node","Route","Timezone","Exit","Udp"}){var s=Ready(now);typeof(Snapshot).GetField(field).SetValue(s,"changed");Check(p.Evaluate(s,now).Stop,"changed "+field);}
 foreach(string field in new[]{"Transport","Dns","EdgeComplete"}){p.Reset();p.Admission=good.Binding();var s=Ready(now);typeof(Snapshot).GetField(field).SetValue(s,false);Check(s.Issue()!="","no admission when missing "+field);Check(p.Evaluate(s,now).Retry,"retry "+field);s.At=now.AddSeconds(119);Check(p.Evaluate(s,s.At).Retry,"grace "+field);s.At=now.AddSeconds(120);Check(p.Evaluate(s,s.At).Stop,"deadline "+field);Check(!p.Evaluate(Ready(s.At),s.At).Retry,"recovery "+field);}
 p.Reset();p.Admission=good.Binding();var partial=Ready(now);partial.EdgeComplete=false;partial.Exit="203.0.113.9";Check(p.Evaluate(partial,now).Stop,"changed single-domain evidence stops");
 var missing=Ready(now);missing.Exit="";missing.EdgeComplete=false;Check(p.Evaluate(missing,now).Retry,"missing trace recovery");missing=Ready(now);missing.Udp="";Check(p.Evaluate(missing,now).Retry,"missing UDP recovery");Check(!p.Evaluate(good,now).Retry,"fresh evidence resets recovery");
 var stale=Ready(now.AddSeconds(-46));Check(p.Evaluate(stale,now).Stop,"stale");Check(p.Evaluate(good,now.AddSeconds(-1)).Stop,"clock rollback");p.Reset();Check(p.Evaluate(good,now).Stop,"no admission");
 return count;}
}
}
