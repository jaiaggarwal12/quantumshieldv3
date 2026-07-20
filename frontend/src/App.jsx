import { useState, useEffect, useRef, useCallback } from "react";

// ── Design Tokens — Light Banking Theme ───────────────────────────────────────
const T = {
  bg:        "#F7F8FC",   // page background - off-white
  surface:   "#FFFFFF",   // cards, panels
  surface2:  "#F0F2F8",   // secondary panels
  border:    "#DDE1EE",   // borders
  border2:   "#C8CDE0",   // stronger borders
  text:      "#1A1D2E",   // primary text
  text2:     "#5A6080",   // secondary text
  text3:     "#9AA0BC",   // muted text
  brand:     "#1B3FAB",   // PNB blue
  brand2:    "#15307D",  // darker brand
  accent:    "#2563EB",   // action blue
  accentHov: "#1D4ED8",   // hover
  success:   "#059669",   // green
  warning:   "#D97706",   // amber
  danger:    "#DC2626",   // red
  purple:    "#7C3AED",   // ai purple
};

const RISK_COLOR = {
  QUANTUM_SAFE:  { bg:"#ECFDF5", border:"#059669", text:"#065F46", badge:"QUANTUM SAFE",  glow:"#05966920" },
  PQC_READY:     { bg:"#FFFBEB", border:"#D97706", text:"#92400E", badge:"PQC READY",     glow:"#D9770620" },
  TRANSITIONING: { bg:"#FFF7ED", border:"#EA580C", text:"#7C2D12", badge:"TRANSITIONING", glow:"#EA580C20" },
  VULNERABLE:    { bg:"#FEF2F2", border:"#DC2626", text:"#7F1D1D", badge:"VULNERABLE",    glow:"#DC262620" },
  UNKNOWN:       { bg:"#EFF6FF", border:"#2563EB", text:"#1E3A8A", badge:"UNKNOWN",       glow:"#2563EB20" },
};
const SEV_COLOR = { CRITICAL:"#DC2626", HIGH:"#EA580C", MEDIUM:"#D97706", LOW:"#059669", INFO:"#2563EB" };

// ── Scan Function ─────────────────────────────────────────────────────────────
// Always hits the real backend. Never fabricates — a failed scan returns an
// honest error object that the UI surfaces as such.
async function performScan(target, backendUrl, token) {
  const clean = target.replace(/^https?:\/\//,"").split("/")[0].trim();
  try {
    const res = await fetch(`${backendUrl}/api/v1/scan/quick`, {
      method:"POST",
      headers:{"Content-Type":"application/json","Authorization":`Bearer ${token}`},
      body: JSON.stringify({target:clean,port:443}),
      signal: AbortSignal.timeout(25000),
    });
    if (res.ok) return await res.json();
    let detail = `Scan failed (HTTP ${res.status})`;
    try { const j = await res.json(); if (j.detail) detail = j.detail; } catch(_){}
    return { target: clean, port:443, status:"error", error: detail, errors:[detail] };
  } catch(e) {
    return { target: clean, port:443, status:"error",
             error:"Could not reach the backend or the scan timed out.",
             errors:["network_error"] };
  }
}

// ── Mini UI Components ────────────────────────────────────────────────────────
function ScoreRing({score,size=72}) {
  const strokeWidth = size > 60 ? 6 : size > 40 ? 4 : 3;
  const r = size/2 - strokeWidth/2 - 1.5;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;
  const color = score >= 75 ? "#059669" : score >= 55 ? "#16A34A" : score >= 35 ? "#EA580C" : "#DC2626";
  return (
    <svg width={size} height={size} style={{ display: "block" }}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#E2E8F0" strokeWidth={strokeWidth}/>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={strokeWidth}
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
        transform={`rotate(-90 ${size/2} ${size/2})`}
        style={{transition:"stroke-dasharray 1.2s ease"}}/>
      <text x={size/2} y={size/2} textAnchor="middle" dominantBaseline="central"
        fill={color} fontSize={size > 60 ? 15 : size > 40 ? 12 : 9.5} fontWeight="800"
        style={{fontFamily:"inherit"}}>{score}</text>
    </svg>
  );
}
function Badge({status,small}) {
  const c=RISK_COLOR[status]||RISK_COLOR.UNKNOWN;
  return <span style={{background:c.bg,border:`1px solid ${c.border}`,color:c.text,
    padding:small?"2px 7px":"3px 10px",borderRadius:4,fontSize:small?10:11,fontWeight:700,
    letterSpacing:1,fontFamily:"inherit",boxShadow:`0 0 8px ${c.glow}`,whiteSpace:"nowrap"}}>{c.badge}</span>;
}
function SevBadge({sev}) {
  const c=SEV_COLOR[sev]||"#888";
  return <span style={{background:`${c}22`,color:c,border:`1px solid ${c}44`,
    padding:"1px 7px",borderRadius:3,fontSize:10,fontWeight:700,letterSpacing:1,whiteSpace:"nowrap"}}>{sev}</span>;
}
function GradeBadge({grade}) {
  const gc={A:"#059669",B:"#16A34A",C:"#EA580C",D:"#EF4444",F:"#DC2626"};
  const c=gc[grade]||"#888";
  return <span style={{background:`${c}22`,color:c,border:`1px solid ${c}`,
    padding:"2px 8px",borderRadius:4,fontSize:12,fontWeight:900,fontFamily:"inherit"}}>{grade}</span>;
}

// ── Login Screen ──────────────────────────────────────────────────────────────
function LoginScreen({backendUrl, onBackendUrlChange, onLogin}) {
  const [step,    setStep]    = useState("password"); // "password" | "otp"
  const [form,    setForm]    = useState({username:"", password:""});
  const [otp,     setOtp]     = useState("");
  const [email,   setEmail]   = useState(""); // masked email shown after step 1
  const [devOtp,  setDevOtp]  = useState(""); // shown when SMTP not configured
  const [error,   setError]   = useState("");
  const [loading, setLoading] = useState(false);
  const [resent,  setResent]  = useState(false);
  const [demoInfo, setDemoInfo] = useState(() => {
    try {
      const cached = localStorage.getItem("qs_demo_info");
      return cached ? JSON.parse(cached) : null;
    } catch (_) {
      return null;
    }
  });

  useEffect(() => {
    let active = true;
    let retries = 0;
    const maxRetries = 15; // 15 retries * 3s = 45s (covers Render spin-up time)

    const fetchDemoInfo = () => {
      if (!active) return;
      fetch(`${backendUrl}/api/v1/auth/demo-info`)
        .then(res => {
          if (!res.ok) throw new Error("Server error");
          return res.json();
        })
        .then(data => {
          if (active) {
            if (data && data.enabled) {
              setDemoInfo(data);
              localStorage.setItem("qs_demo_info", JSON.stringify(data));
            } else {
              setDemoInfo(null);
              localStorage.removeItem("qs_demo_info");
            }
          }
        })
        .catch(() => {
          if (active && retries < maxRetries) {
            retries++;
            setTimeout(fetchDemoInfo, 3000);
          }
        });
    };

    fetchDemoInfo();
    return () => {
      active = false;
    };
  }, [backendUrl]);

  const inp = {
    width:"100%", background:"#FFFFFF", border:"1px solid #DDE1EE",
    borderRadius:7, color:"#1A1D2E", fontFamily:"inherit", fontSize:14,
    padding:"11px 14px", outline:"none", boxSizing:"border-box",
  };

  // Step 1: submit username + password → OTP sent, OR (demo account) instant login.
  const _finishLogin = (data) => {
    const u = {username:data.username, role:data.role, email:data.email, id:data.user_id};
    localStorage.setItem("qs_token", data.access_token);
    localStorage.setItem("qs_user", JSON.stringify(u));
    onLogin(data.access_token, u);
  };

  const doPassword = async () => {
    if(!form.username||!form.password){ setError("Enter your username and password"); return; }
    setLoading(true); setError("");
    const fd = new URLSearchParams();
    fd.append("username", form.username); fd.append("password", form.password);
    try {
      const res = await fetch(`${backendUrl}/api/v1/auth/login`,
        {method:"POST", body:fd, signal:AbortSignal.timeout(15000)});
      const data = await res.json().catch(()=>({}));
      if(res.ok) {
        // OTP-bypassed accounts (demo) return a token immediately.
        if(data.otp_required === false && data.access_token){ _finishLogin(data); return; }
        setEmail(data.email || "");
        setStep("otp");
      } else {
        setError(data.detail || "Invalid username or password");
      }
    } catch(_) {
      setError("Cannot reach the server. It may be waking up — try again in a moment.");
    }
    setLoading(false);
  };

  // One-click public demo login (no OTP).
  const quickDemo = async () => {
    if(!demoInfo) return;
    setLoading(true); setError("");
    const fd = new URLSearchParams();
    fd.append("username", demoInfo.username); fd.append("password", demoInfo.password);
    try {
      const res = await fetch(`${backendUrl}/api/v1/auth/login`,
        {method:"POST", body:fd, signal:AbortSignal.timeout(15000)});
      const data = await res.json().catch(()=>({}));
      if(res.ok && data.access_token){ _finishLogin(data); return; }
      setError(data.detail || "Demo login failed — please try again");
    } catch(_) { setError("Cannot reach the server. It may be waking up — try again."); }
    setLoading(false);
  };

  // Step 2: submit OTP → get JWT token
  const doOtp = async () => {
    if(otp.length !== 6){ setError("Enter the 6-digit code from your email"); return; }
    setLoading(true); setError("");
    try {
      const res = await fetch(`${backendUrl}/api/v1/auth/verify-otp`, {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({email, otp}),
        signal: AbortSignal.timeout(10000)
      });
      if(res.ok) {
        const data = await res.json();
        const user = {username:data.username, role:data.role, email:data.email, id:data.user_id};
        localStorage.setItem("qs_token", data.access_token);
        localStorage.setItem("qs_user", JSON.stringify(user));
        onLogin(data.access_token, user);
      } else {
        const d = await res.json().catch(()=>({}));
        setError(d.detail || "Incorrect code — please try again");
      }
    } catch(_){ setError("Network error — please try again"); }
    setLoading(false);
  };

  const resendOtp = async () => {
    setResent(false);
    try {
      await fetch(`${backendUrl}/api/v1/auth/resend-otp`,
        {method:"POST", headers:{"Content-Type":"application/json"},
         body:JSON.stringify({email})});
      setResent(true); setTimeout(()=>setResent(false), 4000);
    } catch(_){}
  };

  // Mask email for display: j***@example.com
  const maskEmail = (e) => {
    if(!e) return "";
    const [local, domain] = e.split("@");
    if(!domain) return e;
    return local[0] + "***@" + domain;
  };

  const roleColor = {Admin:"#1B3FAB", Operator:"#059669", Checker:"#D97706"};

  return (
    <div style={{background:"#F0F4FF", minHeight:"100vh", display:"flex",
      alignItems:"center", justifyContent:"center", fontFamily:"'Segoe UI',Arial,sans-serif", padding:20}}>
      <div style={{width:"100%", maxWidth:420}}>

        {/* Logo */}
        <div style={{textAlign:"center", marginBottom:28}}>
          <div style={{width:56,height:56,background:"linear-gradient(135deg,#1B3FAB,#2563EB)",
            borderRadius:14,display:"flex",alignItems:"center",justifyContent:"center",
            fontSize:26,margin:"0 auto 12px",boxShadow:"0 4px 20px #1B3FAB25"}}>⚛</div>
          <div style={{color:"#1A1D2E",fontWeight:800,fontSize:22,letterSpacing:0.5}}>QuantumShield</div>
          <div style={{color:"#5A6080",fontSize:12,marginTop:3}}>PQC Scanner · NIST FIPS 203/204/205</div>
        </div>

        <div style={{background:"#FFFFFF",border:"1px solid #DDE1EE",borderRadius:14,
          padding:"32px",boxShadow:"0 4px 24px #1B3FAB0A"}}>

          {/* ── STEP 1: Password ── */}
          {step === "password" && (<>
            <div style={{color:"#1A1D2E",fontWeight:700,fontSize:16,marginBottom:6}}>Sign in</div>
            <div style={{color:"#6B7280",fontSize:13,marginBottom:24}}>
              Enter your credentials. A one-time code will be sent to your registered email.
            </div>

            {error && <div style={{background:"#FEF2F2",border:"1px solid #FECACA",color:"#DC2626",
              padding:"10px 14px",borderRadius:7,marginBottom:16,fontSize:13}}>{error}</div>}

            <div style={{marginBottom:14}}>
              <label style={{color:"#374151",fontSize:13,fontWeight:600,display:"block",marginBottom:6}}>
                Username
              </label>
              <input value={form.username}
                onChange={e=>setForm({...form,username:e.target.value})}
                onKeyDown={e=>e.key==="Enter"&&doPassword()}
                style={inp} placeholder="Enter username" autoFocus/>
            </div>
            <div style={{marginBottom:24}}>
              <label style={{color:"#374151",fontSize:13,fontWeight:600,display:"block",marginBottom:6}}>
                Password
              </label>
              <input type="password" value={form.password}
                onChange={e=>setForm({...form,password:e.target.value})}
                onKeyDown={e=>e.key==="Enter"&&doPassword()}
                style={inp} placeholder="••••••••"/>
            </div>

            <button onClick={doPassword} disabled={loading} style={{
              width:"100%",padding:"12px",background:loading?"#93A5D4":"linear-gradient(135deg,#1B3FAB,#2563EB)",
              border:"none",borderRadius:8,color:"#fff",fontSize:14,fontWeight:700,
              cursor:loading?"not-allowed":"pointer",boxShadow:"0 2px 12px #1B3FAB25",fontFamily:"inherit"}}>
              {loading ? "Signing in..." : "Continue →"}
            </button>

            {/* Public demo account — instant access, no OTP */}
            {demoInfo && (
              <div style={{marginTop:20,paddingTop:18,borderTop:"1px solid #EEF0F8"}}>
                <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:10}}>
                  <div style={{flex:1,height:1,background:"#EEF0F8"}}/>
                  <span style={{color:"#9CA3AF",fontSize:11,letterSpacing:1}}>TRY THE LIVE DEMO</span>
                  <div style={{flex:1,height:1,background:"#EEF0F8"}}/>
                </div>
                <div style={{background:"#F0F4FF",border:"1px solid #DDE6FF",borderRadius:10,padding:"12px 14px"}}>
                  <div style={{display:"flex",justifyContent:"space-between",fontSize:12,marginBottom:4}}>
                    <span style={{color:"#5A6080"}}>Username</span>
                    <code style={{color:"#1B3FAB",fontWeight:700}}>{demoInfo.username}</code>
                  </div>
                  <div style={{display:"flex",justifyContent:"space-between",fontSize:12}}>
                    <span style={{color:"#5A6080"}}>Password</span>
                    <code style={{color:"#1B3FAB",fontWeight:700}}>{demoInfo.password}</code>
                  </div>
                </div>
                <button onClick={quickDemo} disabled={loading} style={{
                  width:"100%",marginTop:10,padding:"11px",background:"#FFFFFF",
                  border:"1px solid #1B3FAB",borderRadius:8,color:"#1B3FAB",fontSize:13,fontWeight:700,
                  cursor:loading?"not-allowed":"pointer",fontFamily:"inherit"}}>
                  ⚡ Sign in as Demo — no OTP
                </button>
                <div style={{color:"#9CA3AF",fontSize:11,textAlign:"center",marginTop:8}}>
                  Full real functionality · live scans · no email code needed
                </div>
              </div>
            )}
          </>)}

          {/* ── STEP 2: Email OTP ── */}
          {step === "otp" && (<>
            <div style={{textAlign:"center",marginBottom:24}}>
              <div style={{fontSize:44,marginBottom:10}}>📧</div>
              <div style={{color:"#1A1D2E",fontWeight:700,fontSize:16,marginBottom:8}}>
                Check your email
              </div>
              <div style={{color:"#5A6080",fontSize:13,lineHeight:1.6}}>
                We sent a 6-digit code to<br/>
                <strong style={{color:"#1A1D2E"}}>{maskEmail(email)}</strong>
              </div>
            </div>

            {/* Dev mode OTP display */}
            {devOtp && (
              <div style={{background:"#ECFDF5",border:"1px solid #A7F3D0",borderRadius:8,
                padding:"12px",textAlign:"center",marginBottom:16}}>
                <div style={{color:"#065F46",fontSize:11,fontWeight:600,marginBottom:4}}>
                  DEV MODE — No SMTP configured. Your OTP:
                </div>
                <div style={{fontSize:28,fontWeight:900,letterSpacing:8,color:"#059669",
                  fontFamily:"'Courier New',monospace"}}>{devOtp}</div>
                <div style={{color:"#6B7280",fontSize:11,marginTop:4}}>
                  Set SMTP_USER + SMTP_PASSWORD on Render to send real emails
                </div>
              </div>
            )}

            {error && <div style={{background:"#FEF2F2",border:"1px solid #FECACA",color:"#DC2626",
              padding:"10px 14px",borderRadius:7,marginBottom:16,fontSize:13}}>{error}</div>}

            {resent && <div style={{background:"#ECFDF5",border:"1px solid #A7F3D0",color:"#065F46",
              padding:"10px 14px",borderRadius:7,marginBottom:16,fontSize:13}}>
              ✓ New code sent to {maskEmail(email)}
            </div>}

            {/* OTP input */}
            <input
              value={otp}
              onChange={e=>setOtp(e.target.value.replace(/\D/g,"").slice(0,6))}
              onKeyDown={e=>e.key==="Enter"&&doOtp()}
              style={{...inp, textAlign:"center", fontSize:28, letterSpacing:10,
                fontWeight:800, fontFamily:"'Courier New',monospace", marginBottom:16}}
              placeholder="000000" maxLength={6} autoFocus/>

            <button onClick={doOtp} disabled={loading||otp.length!==6} style={{
              width:"100%",padding:"12px",
              background:otp.length===6&&!loading?"linear-gradient(135deg,#1B3FAB,#2563EB)":"#93A5D4",
              border:"none",borderRadius:8,color:"#fff",fontSize:14,fontWeight:700,
              cursor:otp.length===6&&!loading?"pointer":"not-allowed",fontFamily:"inherit",
              marginBottom:12}}>
              {loading ? "Verifying..." : "Verify Code →"}
            </button>

            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <button onClick={()=>{setStep("password");setError("");setOtp("");setDevOtp("");}}
                style={{background:"none",border:"none",color:"#5A6080",fontSize:13,
                  cursor:"pointer",padding:0,fontFamily:"inherit"}}>
                ← Back
              </button>
              <button onClick={resendOtp}
                style={{background:"none",border:"none",color:"#1B3FAB",fontSize:13,
                  cursor:"pointer",padding:0,fontFamily:"inherit",fontWeight:600}}>
                Resend code
              </button>
            </div>
          </>)}

        </div>

        <div style={{textAlign:"center",marginTop:20,color:"#9CA3AF",fontSize:12}}>
          QuantumShield · Post-Quantum Cryptography Scanner
        </div>
      </div>
    </div>
  );
}

function HistoryPanel({backendUrl,token,onLoadScan}) {
  const [history,setHistory]=useState([]);
  const [loading,setLoading]=useState(true);
  const [loadingId,setLoadingId]=useState(null);
  const [deletingId,setDeletingId]=useState(null);

  const fetchHistory=useCallback(async()=>{
    setLoading(true);
    try {
      const res=await fetch(`${backendUrl}/api/v1/history`,{headers:{"Authorization":`Bearer ${token}`}});
      if(res.ok) setHistory(await res.json());
    } catch(_){}
    setLoading(false);
  },[backendUrl,token]);

  useEffect(()=>{fetchHistory();},[fetchHistory]);

  const loadScan=async(id)=>{
    setLoadingId(id);
    try {
      const res=await fetch(`${backendUrl}/api/v1/history/${id}`,{headers:{"Authorization":`Bearer ${token}`}});
      if(res.ok){const d=await res.json();onLoadScan(d);}
    } catch(_){}
    setLoadingId(null);
  };

  const deleteScan=async(id,e)=>{
    e.stopPropagation();
    setDeletingId(id);
    try {
      await fetch(`${backendUrl}/api/v1/history/${id}`,{method:"DELETE",headers:{"Authorization":`Bearer ${token}`}});
      setHistory(h=>h.filter(s=>s.id!==id));
    } catch(_){}
    setDeletingId(null);
  };

  if(loading) return <div style={{color:"#9CA3AF",padding:40,textAlign:"center",fontFamily:"inherit"}}>Loading history...</div>;

  return (
    <div style={{padding:"20px 24px",maxWidth:900,margin:"0 auto"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
        <div>
          <div style={{color:"#1A1D2E",fontWeight:700,fontSize:16,fontFamily:"inherit"}}>📋 SCAN HISTORY</div>
          <div style={{color:"#9CA3AF",fontSize:11,marginTop:3}}>{history.length} scans stored in database</div>
        </div>
        <button onClick={fetchHistory} style={{background:"#F7F8FC",border:"1px solid #DDE1EE",color:"#6B7280",
          padding:"6px 14px",borderRadius:6,cursor:"pointer",fontFamily:"inherit",fontSize:11}}>↻ REFRESH</button>
      </div>
      {history.length===0?(
        <div style={{textAlign:"center",padding:"60px 0",color:"#E5E7EB"}}>
          <div style={{fontSize:48,marginBottom:12}}>📭</div>
          <div style={{fontSize:14,color:"#9CA3AF"}}>No scans yet. Run a scan to see history here.</div>
        </div>
      ):(
        <div style={{display:"grid",gap:8}}>
          {history.map(s=>{
            const c=RISK_COLOR[s.pqc_status]||RISK_COLOR.UNKNOWN;
            const date=s.created_at?new Date(s.created_at).toLocaleString():"—";
            return (
              <div key={s.id} onClick={()=>loadScan(s.id)} style={{
                background:"#F7F8FC",border:`1px solid ${c.border}30`,borderLeft:`3px solid ${c.border}`,
                borderRadius:9,padding:"13px 16px",cursor:"pointer",transition:"all 0.2s",
                display:"flex",justifyContent:"space-between",alignItems:"center",
                opacity:loadingId===s.id?0.7:1}}>
                <div>
                  <div style={{color:"#1A1D2E",fontFamily:"inherit",fontWeight:700,fontSize:13}}>🔒 {s.target}</div>
                  <div style={{color:"#9CA3AF",fontSize:11,marginTop:3}}>{s.tls_version||"—"} · {date}</div>
                </div>
                <div style={{display:"flex",alignItems:"center",gap:10}}>
                  <ScoreRing score={s.pqc_score||0} size={40}/>
                  <Badge status={s.pqc_status} small/>
                  <button onClick={e=>deleteScan(s.id,e)} disabled={deletingId===s.id} style={{
                    background:"#FEF2F2",border:"1px solid #ff174430",color:"#DC2626",
                    padding:"4px 8px",borderRadius:5,cursor:"pointer",fontSize:11,fontFamily:"inherit"}}>
                    {deletingId===s.id?"...":"✕"}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── User Management Panel (Admin only) ────────────────────────────────────────
function UserManagement({backendUrl,token,currentUser}) {
  const [users,setUsers]=useState([]);
  const [loading,setLoading]=useState(true);
  const [newUser,setNewUser]=useState({username:"",email:"",password:"",role:"Operator"});
  const [creating,setCreating]=useState(false);
  const [error,setError]=useState("");
  const [success,setSuccess]=useState("");

  const fetchUsers=useCallback(async()=>{
    setLoading(true);
    try {
      const res=await fetch(`${backendUrl}/api/v1/auth/users`,{headers:{"Authorization":`Bearer ${token}`}});
      if(res.ok) setUsers(await res.json());
    } catch(_){}
    setLoading(false);
  },[backendUrl,token]);

  useEffect(()=>{fetchUsers();},[fetchUsers]);

  const createUser=async()=>{
    if(!newUser.username||!newUser.email||!newUser.password){setError("All fields required");return;}
    setCreating(true);setError("");
    try {
      const res=await fetch(`${backendUrl}/api/v1/auth/users`,{
        method:"POST",headers:{"Content-Type":"application/json","Authorization":`Bearer ${token}`},
        body:JSON.stringify(newUser)});
      if(res.ok){
        setSuccess("User created successfully");
        setNewUser({username:"",email:"",password:"",role:"Operator"});
        fetchUsers();
        setTimeout(()=>setSuccess(""),3000);
      } else {
        const d=await res.json().catch(()=>({}));
        setError(d.detail||"Failed to create user");
      }
    } catch(_){setError("Request failed");}
    setCreating(false);
  };

  const toggleUser=async(id)=>{
    try {
      const res=await fetch(`${backendUrl}/api/v1/auth/users/${id}/toggle`,{method:"PUT",headers:{"Authorization":`Bearer ${token}`}});
      if(res.ok) fetchUsers();
    } catch(_){}
  };

  const deleteUser=async(id,uname)=>{
    if(!window.confirm(`Delete user "${uname}"?`)) return;
    try {
      const res=await fetch(`${backendUrl}/api/v1/auth/users/${id}`,{method:"DELETE",headers:{"Authorization":`Bearer ${token}`}});
      if(res.ok) setUsers(u=>u.filter(x=>x.id!==id));
    } catch(_){}
  };

  const inp={width:"100%",background:"#FFFFFF",border:"1px solid #DDE1EE",borderRadius:7,
    color:"#1A1D2E",fontFamily:"inherit",fontSize:12,padding:"9px 12px",outline:"none",boxSizing:"border-box"};
  const roleColor={Admin:"#a78bfa",Operator:"#60a5fa",Checker:"#34d399"};

  return (
    <div style={{padding:"20px 24px",maxWidth:900,margin:"0 auto"}}>
      <div style={{color:"#1A1D2E",fontWeight:700,fontSize:16,fontFamily:"inherit",marginBottom:20}}>👥 USER MANAGEMENT</div>

      {/* Create User */}
      <div style={{background:"#F7F8FC",border:"1px solid #DDE1EE",borderRadius:12,padding:"20px",marginBottom:24}}>
        <div style={{color:"#1B3FAB",fontSize:12,fontWeight:700,letterSpacing:1,marginBottom:14}}>CREATE NEW USER</div>
        {error&&<div style={{background:"#ff174415",border:"1px solid #ff174440",color:"#DC2626",padding:"8px 12px",borderRadius:6,marginBottom:12,fontSize:12}}>{error}</div>}
        {success&&<div style={{background:"#00e67615",border:"1px solid #00e67640",color:"#059669",padding:"8px 12px",borderRadius:6,marginBottom:12,fontSize:12}}>{success}</div>}
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:10}}>
          <div><div style={{color:"#9CA3AF",fontSize:10,letterSpacing:1,marginBottom:5}}>USERNAME</div><input value={newUser.username} onChange={e=>setNewUser({...newUser,username:e.target.value})} style={inp} placeholder="johndoe"/></div>
          <div><div style={{color:"#9CA3AF",fontSize:10,letterSpacing:1,marginBottom:5}}>EMAIL</div><input value={newUser.email} onChange={e=>setNewUser({...newUser,email:e.target.value})} style={inp} placeholder="john@example.com"/></div>
          <div><div style={{color:"#9CA3AF",fontSize:10,letterSpacing:1,marginBottom:5}}>PASSWORD</div><input type="password" value={newUser.password} onChange={e=>setNewUser({...newUser,password:e.target.value})} style={inp} placeholder="••••••••"/></div>
          <div><div style={{color:"#9CA3AF",fontSize:10,letterSpacing:1,marginBottom:5}}>ROLE</div>
            <select value={newUser.role} onChange={e=>setNewUser({...newUser,role:e.target.value})}
              style={{...inp,cursor:"pointer"}}>
              <option value="Operator">Operator</option>
              <option value="Checker">Checker</option>
              <option value="Admin">Admin</option>
            </select>
          </div>
        </div>
        <button onClick={createUser} disabled={creating} style={{
          background:creating?"#93A5D4":"linear-gradient(135deg,#1B3FAB,#2563EB)",
          border:"none",borderRadius:7,color:"#fff",padding:"10px 24px",
          fontFamily:"inherit",fontSize:12,fontWeight:700,cursor:creating?"not-allowed":"pointer",letterSpacing:1}}>
          {creating?"CREATING...":"+ CREATE USER"}
        </button>
      </div>

      {/* User List */}
      {loading?(
        <div style={{color:"#9CA3AF",padding:20,textAlign:"center",fontFamily:"inherit"}}>Loading users...</div>
      ):(
        <div style={{display:"grid",gap:8}}>
          {users.map(u=>(
            <div key={u.id} style={{background:"#F7F8FC",border:"1px solid #DDE1EE",borderRadius:9,
              padding:"13px 16px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <div>
                <div style={{display:"flex",alignItems:"center",gap:10}}>
                  <span style={{color:"#1A1D2E",fontFamily:"inherit",fontWeight:700,fontSize:13}}>{u.username}</span>
                  <span style={{background:`${roleColor[u.role]||"#888"}22`,color:roleColor[u.role]||"#888",
                    border:`1px solid ${roleColor[u.role]||"#888"}44`,padding:"1px 8px",borderRadius:4,fontSize:10,fontWeight:700}}>{u.role}</span>
                  {!u.is_active&&<span style={{background:"#ff174420",color:"#DC2626",border:"1px solid #ff174440",padding:"1px 8px",borderRadius:4,fontSize:10}}>DISABLED</span>}
                  {u.username===currentUser.username&&<span style={{color:"#9CA3AF",fontSize:10}}>(you)</span>}
                </div>
                <div style={{color:"#9CA3AF",fontSize:11,marginTop:3}}>{u.email} · Joined {u.created_at?new Date(u.created_at).toLocaleDateString():"—"}</div>
              </div>
              {u.username!==currentUser.username&&(
                <div style={{display:"flex",gap:8}}>
                  <button onClick={()=>toggleUser(u.id)} style={{
                    background:u.is_active?"#FFF7ED":"#ECFDF5",
                    border:`1px solid ${u.is_active?"#FED7AA":"#A7F3D0"}`,
                    color:u.is_active?"#D97706":"#059669",padding:"5px 12px",borderRadius:6,
                    cursor:"pointer",fontFamily:"inherit",fontSize:11}}>
                    {u.is_active?"DISABLE":"ENABLE"}
                  </button>
                  <button onClick={()=>deleteUser(u.id,u.username)} style={{
                    background:"#FEF2F2",border:"1px solid #ff174430",color:"#DC2626",
                    padding:"5px 12px",borderRadius:6,cursor:"pointer",fontFamily:"inherit",fontSize:11}}>DELETE</button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Summary Bar ───────────────────────────────────────────────────────────────
function SummaryBar({results}) {
  if(!results.length) return null;
  const c={QUANTUM_SAFE:0,PQC_READY:0,TRANSITIONING:0,VULNERABLE:0};
  results.forEach(r=>{const s=r.pqc_assessment?.status;if(s in c)c[s]++;});
  const avgScore=results.length?Math.round(results.reduce((a,r)=>a+(r.pqc_assessment?.score||0),0)/results.length):0;
  return (
    <div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:12}}>
        {Object.entries(c).map(([status,count])=>{
          const rc=RISK_COLOR[status];
          return <div key={status} style={{background:rc.bg,border:`1px solid ${rc.border}30`,borderRadius:8,padding:"12px 14px"}}>
            <div style={{color:rc.text,fontSize:26,fontWeight:900,fontFamily:"inherit"}}>{count}</div>
            <div style={{color:rc.border,fontSize:10,fontWeight:700,letterSpacing:1,marginTop:3}}>{rc.badge}</div>
          </div>;
        })}
      </div>
      <div style={{background:"#F7F8FC",border:"1px solid #DDE1EE",borderRadius:8,padding:"12px 16px",marginBottom:16,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <span style={{color:"#9CA3AF",fontSize:12}}>FLEET AVG SCORE</span>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <div style={{width:200,height:6,background:"#EEF2FF",borderRadius:3,overflow:"hidden"}}>
            <div style={{width:`${avgScore}%`,height:"100%",background:"linear-gradient(90deg,#DC2626,#EA580C,#D97706,#059669)",borderRadius:3,transition:"width 1s ease"}}/>
          </div>
          <span style={{color:"#1A1D2E",fontWeight:700,fontFamily:"inherit",fontSize:14}}>{avgScore}/100</span>
        </div>
      </div>
    </div>
  );
}

// ── Vuln / CBOM / DNS / Headers Panels (unchanged from original) ──────────────
function VulnPanel({vulns}) {
  if(!vulns?.length) return <div style={{color:"#3a5a3a",fontSize:13,padding:"20px 0"}}>✓ No known classical vulnerabilities detected</div>;
  return <div style={{display:"flex",flexDirection:"column",gap:8}}>
    {vulns.map((v,i)=>(
      <div key={i} style={{background:"#FEF2F2",border:`1px solid ${SEV_COLOR[v.severity]||"#333"}30`,
        borderLeft:`3px solid ${SEV_COLOR[v.severity]||"#333"}`,borderRadius:6,padding:"10px 14px"}}>
        <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4,flexWrap:"wrap"}}>
          <SevBadge sev={v.severity}/>
          <span style={{color:"#7F1D1D",fontWeight:700,fontSize:13,fontFamily:"inherit"}}>{v.name}</span>
          {v.cve!=="N/A"&&<span style={{color:"#6B7280",fontSize:11,fontFamily:"inherit"}}>{v.cve}</span>}
        </div>
        <div style={{color:"#374151",fontSize:12,marginBottom:4}}>{v.description}</div>
        <div style={{color:"#4B5563",fontSize:11}}>→ {v.action}</div>
      </div>
    ))}
  </div>;
}

function CBOMTable({components}) {
  const icons={protocol:"🔗","cipher-suite":"🔐",certificate:"📜","key-exchange":"🔑"};
  return <div style={{overflowX:"auto"}}>
    <table style={{width:"100%",borderCollapse:"collapse",fontFamily:"inherit",fontSize:12}}>
      <thead><tr style={{borderBottom:"1px solid #DDE1EE"}}>
        {["Type","Name","Details","Forward Secrecy","Quantum Status"].map(h=>(
          <th key={h} style={{padding:"8px 12px",textAlign:"left",color:"#9CA3AF",fontWeight:600,fontSize:10,letterSpacing:1}}>{h.toUpperCase()}</th>
        ))}
      </tr></thead>
      <tbody>{components?.map((c,i)=>(
        <tr key={i} style={{borderBottom:"1px solid #EEF0F8"}}>
          <td style={{padding:"9px 12px",color:"#9999cc"}}>{icons[c.type]||"·"} {c.type}</td>
          <td style={{padding:"9px 12px",color:"#1A1D2E",fontWeight:600,wordBreak:"break-all",maxWidth:200}}>{c.name}</td>
          <td style={{padding:"9px 12px",color:"#6B7280"}}>
            {c.bits?`${c.bits}-bit`:""} {c.version||""} {c.grade?<GradeBadge grade={c.grade}/>:""}
            {c.days_until_expiry!=null?<span style={{color:c.days_until_expiry<30?"#EF4444":"#6688aa",fontSize:11,marginLeft:4}}>{c.days_until_expiry}d</span>:""}
          </td>
          <td style={{padding:"9px 12px"}}>
            {c.forward_secrecy===true?<span style={{color:"#059669"}}>✓ YES</span>:c.forward_secrecy===false?<span style={{color:"#DC2626"}}>✗ NO</span>:<span style={{color:"#9CA3AF"}}>—</span>}
          </td>
          <td style={{padding:"9px 12px"}}>
            {c.quantum_safe?<span style={{color:"#059669",fontWeight:700}}>✓ QUANTUM SAFE</span>:<span style={{color:"#DC2626",fontWeight:700}}>✗ VULNERABLE</span>}
          </td>
        </tr>
      ))}</tbody>
    </table>
  </div>;
}

function DNSPanel({dns}) {
  if(!dns||!Object.keys(dns).length) return <div style={{color:"#444466",fontSize:13}}>DNS data not available</div>;
  const items=[
    ["DNS Resolves",dns.dns_resolves?"✓ Yes":"✗ No",dns.dns_resolves?"#059669":"#EF4444"],
    ["IPv4 Addresses",dns.ipv4_addresses?.join(", ")||"None","#8c9eff"],
    ["IPv6 Addresses",dns.ipv6_addresses?.join(", ")||"None",dns.ipv6_addresses?.length?"#8c9eff":"#D97706"],
    ["CAA Records",dns.caa_present?"✓ Present":"✗ Missing",dns.caa_present?"#059669":"#EF4444"],
    ["DNSSEC",dns.dnssec_enabled?"✓ Enabled":"Not detected",dns.dnssec_enabled?"#059669":"#D97706"],
    ["SPF Record",dns.spf_present?"✓ Present":"Not detected",dns.spf_present?"#059669":"#D97706"],
    ["DMARC Record",dns.dmarc_present?"✓ Present":"Not detected",dns.dmarc_present?"#059669":"#D97706"],
  ];
  return <div>
    {items.map(([l,v,c])=>(
      <div key={l} style={{display:"flex",borderBottom:"1px solid #EEF0F8",padding:"9px 0",alignItems:"center"}}>
        <div style={{width:160,color:"#9CA3AF",fontSize:11,flexShrink:0}}>{l}</div>
        <div style={{color:c,fontSize:12,fontFamily:"inherit"}}>{v}</div>
      </div>
    ))}
    {dns.issues?.map((issue,i)=>(
      <div key={i} style={{background:"#FFFBEB",border:`1px solid ${SEV_COLOR[issue.severity]||"#333"}30`,
        borderLeft:`3px solid ${SEV_COLOR[issue.severity]||"#333"}`,borderRadius:6,padding:"8px 12px",marginTop:8}}>
        <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:3}}><SevBadge sev={issue.severity}/><span style={{color:"#1F2937",fontSize:12}}>{issue.issue}</span></div>
        <div style={{color:"#4B5563",fontSize:11}}>→ {issue.action}</div>
      </div>
    ))}
  </div>;
}

function HeadersPanel({http}) {
  if(!http||!Object.keys(http).length) return <div style={{color:"#444466",fontSize:13}}>HTTP header data not available</div>;
  const hsts=http.hsts||{};
  return <div>
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:16}}>
      {[
        ["HSTS",hsts.present?"✓ Present":"✗ Missing",hsts.present?"#059669":"#EF4444"],
        ["HSTS max-age",hsts.max_age?`${hsts.max_age}s`:"—",hsts.max_age>=31536000?"#059669":"#D97706"],
        ["includeSubDomains",hsts.include_subdomains?"✓":"✗",hsts.include_subdomains?"#059669":"#EF4444"],
        ["Preload",hsts.preload?"✓ Yes":"✗ No",hsts.preload?"#059669":"#D97706"],
        ["CSP",http.csp?.present?"✓ Present":"✗ Missing",http.csp?.present?"#059669":"#EF4444"],
        ["Header Score",`${http.score||0}/100`,(http.score||0)>=80?"#059669":(http.score||0)>=60?"#D97706":"#EF4444"],
      ].map(([l,v,c])=>(
        <div key={l} style={{background:"#F7F8FC",border:"1px solid #DDE1EE",borderRadius:6,padding:"10px 12px"}}>
          <div style={{color:"#9CA3AF",fontSize:10,letterSpacing:1,marginBottom:4}}>{l.toUpperCase()}</div>
          <div style={{color:c,fontFamily:"inherit",fontSize:12,fontWeight:700}}>{v}</div>
        </div>
      ))}
    </div>
    {http.headers_missing?.length>0&&(
      <div>
        <div style={{color:"#9CA3AF",fontSize:10,letterSpacing:1,marginBottom:8}}>MISSING SECURITY HEADERS</div>
        <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
          {http.headers_missing.map((h,i)=>(
            <span key={i} style={{background:"#ff174420",border:"1px solid #ff174440",color:"#DC2626",
              padding:"3px 10px",borderRadius:4,fontSize:11,fontFamily:"inherit"}}>{h}</span>
          ))}
        </div>
      </div>
    )}
    {http.issues?.map((issue,i)=>(
      <div key={i} style={{background:"#FFFBEB",border:`1px solid ${SEV_COLOR[issue.severity]||"#333"}30`,
        borderLeft:`3px solid ${SEV_COLOR[issue.severity]||"#333"}`,borderRadius:6,padding:"8px 12px",marginTop:8}}>
        <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:3}}><SevBadge sev={issue.severity}/><span style={{color:"#1F2937",fontSize:12}}>{issue.issue}</span></div>
        <div style={{color:"#4B5563",fontSize:11}}>→ {issue.action}</div>
      </div>
    ))}
  </div>;
}

// ── Detail Panel ──────────────────────────────────────────────────────────────
// ── AI Explanation Panel ──────────────────────────────────────────────────────
function AIPanel({result, backendUrl, token}) {
  const [messages, setMessages] = useState([]);
  const [input, setInput]       = useState("");
  const [loading, setLoading]   = useState(false);
  const [listening, setListening] = useState(false);
  const [audience, setAudience] = useState("ceo");
  const [showExplain, setShowExplain] = useState(false);
  const [explanation, setExplanation] = useState("");
  const [explainLoading, setExplainLoading] = useState(false);
  const [source, setSource] = useState("");
  const chatEndRef = useRef(null);
  const recognitionRef = useRef(null);

  const pqc  = result?.pqc_assessment || {};
  const tls  = result?.tls_info || {};
  const cert = result?.certificate || {};

  const ctx = {
    target: result?.target,
    pqc_score: pqc.score,
    pqc_status: pqc.status,
    tls_version: tls.tls_version,
    cipher_suite: tls.cipher_suite,
    key_exchange: tls.key_exchange,
    cert_key_type: cert.key_type,
    cert_key_bits: cert.key_bits,
    forward_secrecy: tls.forward_secrecy,
    days_until_expiry: cert.days_until_expiry,
    vulnerabilities: result?.vulnerabilities || [],
  };

  useEffect(() => { chatEndRef.current?.scrollIntoView({behavior:"smooth"}); }, [messages]);

  // Seed a welcome message when a new scan is selected
  useEffect(() => {
    if (!result?.target) return;
    setMessages([{
      role: "assistant",
      content: `I've analysed **${result.target}** — score **${pqc.score || 0}/100** (${pqc.status || "UNKNOWN"}). Ask me anything about this result: why it scored this way, what HNDL means for this site, how to fix specific issues, or what ML-KEM/ML-DSA migration looks like.`,
      source: "system"
    }]);
    setExplanation(""); setShowExplain(false);
  }, [result?.target]);

  const _headers = () => {
    const h = {"Content-Type":"application/json"};
    if (token) h["Authorization"] = `Bearer ${token}`;
    return h;
  };

  const sendMessage = async (text) => {
    if (!text.trim()) return;
    const userMsg = {role:"user", content:text};
    const newMsgs = [...messages, userMsg];
    setMessages(newMsgs);
    setInput(""); setLoading(true);

    try {
      const res = await fetch(`${backendUrl}/api/v1/ai/chat`, {
        method:"POST", headers:_headers(),
        body: JSON.stringify({
          messages: newMsgs.filter(m=>m.role!=="system").map(m=>({role:m.role,content:m.content})),
          ...ctx
        }),
        signal: AbortSignal.timeout(30000)
      });
      if (res.ok) {
        const data = await res.json();
        setMessages(m => [...m, {role:"assistant", content:data.response, source:data.source}]);
      } else {
        setMessages(m => [...m, {role:"assistant", content:"Unable to reach AI — check that the backend is running.", source:"error"}]);
      }
    } catch(_) {
      // Local rule-based fallback
      const score = pqc.score || 0;
      const t = result?.target || "this site";
      const c = `${cert.key_type||"?"}-${cert.key_bits||0}`;
      const hasHndl = (result?.vulnerabilities||[]).some(v=>v.name==="HNDL");
      let reply = `${t} scored ${score}/100. `;
      if (text.toLowerCase().includes("hndl") || text.toLowerCase().includes("harvest")) {
        reply = `HNDL (Harvest Now Decrypt Later) means nation-states are recording ${t}'s encrypted traffic today. With ${c} and ${tls.key_exchange||"classical KEX"}, all past sessions become decryptable when quantum computers arrive (~2030). Fix: deploy ML-KEM-768 (FIPS 203) immediately.`;
      } else if (text.toLowerCase().includes("fix") || text.toLowerCase().includes("action")) {
        reply = `For ${t} (${score}/100): 1) Enforce TLS 1.3  2) Deploy X25519+ML-KEM-768 hybrid key exchange (FIPS 203)  3) Replace ${c} cert with ML-DSA-65 (FIPS 204)  Timeline: start steps 1-2 now.`;
      } else if (text.toLowerCase().includes("score") || text.toLowerCase().includes("why")) {
        reply = `${score}/100 deductions: ${c} cert (-20, Shor's breaks it), ${tls.tls_version||"?"} (-8 if TLS 1.2), non-PQC key exchange (-8). To improve: TLS 1.3 + ML-KEM-768 + ML-DSA-65 cert.`;
      }
      setMessages(m => [...m, {role:"assistant", content:reply, source:"local"}]);
    }
    setLoading(false);
  };

  const startVoice = () => {
    if (!("webkitSpeechRecognition" in window) && !("SpeechRecognition" in window)) {
      alert("Voice input not supported in this browser. Try Chrome.");
      return;
    }
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    const rec = new SR();
    rec.lang = "en-IN"; rec.continuous = false; rec.interimResults = false;
    rec.onstart = () => setListening(true);
    rec.onend   = () => setListening(false);
    rec.onresult = (e) => {
      const transcript = e.results[0][0].transcript;
      setInput(transcript);
    };
    rec.onerror = () => setListening(false);
    recognitionRef.current = rec;
    rec.start();
  };

  const generateExplanation = async () => {
    setExplainLoading(true); setExplanation(""); setShowExplain(true);
    try {
      const res = await fetch(`${backendUrl}/api/v1/ai/explain`, {
        method:"POST", headers:_headers(),
        body: JSON.stringify({
          ...ctx, audience,
          top_issues: pqc.issues?.slice(0,3) || [],
        }),
        signal: AbortSignal.timeout(30000)
      });
      if (res.ok) {
        const data = await res.json();
        setExplanation(data.explanation); setSource(data.source || "");
      }
    } catch(_) { setExplanation("Could not generate explanation — backend unavailable."); }
    setExplainLoading(false);
  };

  const quickQ = [
    "Why did it score this low?",
    "What is HNDL and am I at risk?",
    "How do I fix this step by step?",
    "Explain ML-KEM and ML-DSA simply",
  ];

  const srcBadge = (s) => {
    const colors = {gemini:"#1B6EF3", "rule-based":"#D97706", local:"#D97706", system:"#2563EB", error:"#DC2626"};
    const labels = {gemini:"Gemini AI", "rule-based":"Built-in", local:"Built-in", system:"", error:"Error"};
    if (!s || s === "system") return null;
    return <span style={{fontSize:10, color:colors[s]||"#666", background:`${colors[s]||"#666"}15`,
      padding:"1px 7px", borderRadius:10, marginLeft:6, border:`1px solid ${colors[s]||"#666"}30`}}>
      {labels[s]||s}
    </span>;
  };

  if (!result) return (
    <div style={{textAlign:"center", padding:"40px 0", color:"#9CA3AF"}}>
      <div style={{fontSize:40, marginBottom:10}}>🤖</div>
      <div style={{fontSize:13}}>Select a scan result to start chatting</div>
    </div>
  );

  return (
    <div style={{display:"flex", flexDirection:"column", height:"100%", gap:0}}>

      {/* One-shot explain bar */}
      <div style={{padding:"12px 16px", borderBottom:"1px solid #EEF0F8", background:"#F7F8FC", flexShrink:0}}>
        <div style={{display:"flex", gap:6, marginBottom:8}}>
          {[["ceo","🏢 CEO"],["board","📊 Board"],["technical","⚙️ Technical"]].map(([k,v])=>(
            <button key={k} onClick={()=>setAudience(k)} style={{
              flex:1, padding:"6px 4px", borderRadius:6, cursor:"pointer",
              fontSize:11, fontWeight:600, fontFamily:"inherit",
              background:audience===k?"#1B3FAB":"#FFFFFF",
              border:`1px solid ${audience===k?"#1B3FAB":"#DDE1EE"}`,
              color:audience===k?"#FFFFFF":"#374151"}}>
              {v}
            </button>
          ))}
        </div>
        <button onClick={generateExplanation} disabled={explainLoading} style={{
          width:"100%", padding:"8px", borderRadius:7, border:"none", cursor:"pointer",
          background:explainLoading?"#93A5D4":"#1B3FAB", color:"#fff",
          fontSize:12, fontWeight:700, fontFamily:"inherit"}}>
          {explainLoading ? "Generating..." : "✨ Generate Report"}
        </button>
        {showExplain && explanation && (
          <div style={{marginTop:10, padding:"12px", background:"#EFF6FF", borderRadius:8,
            border:"1px solid #BFDBFE", fontSize:12, lineHeight:1.8, color:"#1E3A8A",
            maxHeight:160, overflowY:"auto", whiteSpace:"pre-wrap"}}>
            {explanation}
          </div>
        )}
      </div>

      {/* Chat messages */}
      <div style={{flex:1, overflowY:"auto", padding:"12px 16px"}}>
        {messages.map((m,i) => (
          <div key={i} style={{marginBottom:12, display:"flex",
            flexDirection:m.role==="user"?"row-reverse":"row", gap:8, alignItems:"flex-start"}}>
            <div style={{width:28, height:28, borderRadius:"50%", flexShrink:0, display:"flex",
              alignItems:"center", justifyContent:"center", fontSize:14,
              background:m.role==="user"?"#1B3FAB":"#F0F2F8",
              color:m.role==="user"?"#fff":"#374151"}}>
              {m.role==="user"?"👤":"🤖"}
            </div>
            <div style={{maxWidth:"80%"}}>
              <div style={{padding:"10px 14px", borderRadius:m.role==="user"?"12px 12px 4px 12px":"12px 12px 12px 4px",
                background:m.role==="user"?"#1B3FAB":"#F0F2F8",
                color:m.role==="user"?"#FFFFFF":"#1A1D2E",
                fontSize:13, lineHeight:1.7, whiteSpace:"pre-wrap"}}>
                {m.content}
              </div>
              {m.role==="assistant" && srcBadge(m.source)}
            </div>
          </div>
        ))}
        {loading && (
          <div style={{display:"flex", gap:8, alignItems:"center", padding:"8px 0"}}>
            <div style={{width:28,height:28,borderRadius:"50%",background:"#F0F2F8",
              display:"flex",alignItems:"center",justifyContent:"center"}}>🤖</div>
            <div style={{padding:"10px 14px", background:"#F0F2F8", borderRadius:"12px 12px 12px 4px"}}>
              <div style={{display:"flex", gap:4}}>
                {[0,1,2].map(i=><div key={i} style={{width:6,height:6,borderRadius:"50%",
                  background:"#9CA3AF", animation:`bounce${i} 1s infinite`}}/>)}
              </div>
            </div>
          </div>
        )}
        <div ref={chatEndRef}/>
      </div>

      {/* Quick questions */}
      {messages.length <= 1 && (
        <div style={{padding:"0 16px 10px", display:"flex", flexWrap:"wrap", gap:6}}>
          {quickQ.map((q,i)=>(
            <button key={i} onClick={()=>sendMessage(q)} style={{
              padding:"5px 10px", borderRadius:16, border:"1px solid #DDE1EE",
              background:"#F7F8FC", color:"#374151", fontSize:11, cursor:"pointer",
              fontFamily:"inherit"}}>
              {q}
            </button>
          ))}
        </div>
      )}

      {/* Input bar */}
      <div style={{padding:"10px 12px", borderTop:"1px solid #EEF0F8", background:"#FFFFFF",
        display:"flex", gap:8, alignItems:"center", flexShrink:0}}>
        <input
          value={input}
          onChange={e=>setInput(e.target.value)}
          onKeyDown={e=>e.key==="Enter"&&!e.shiftKey&&sendMessage(input)}
          placeholder="Ask about this scan..."
          style={{flex:1, border:"1px solid #DDE1EE", borderRadius:8, padding:"9px 12px",
            fontSize:13, fontFamily:"inherit", outline:"none", background:"#F7F8FC", color:"#1A1D2E"}}
        />
        <button onClick={startVoice} title="Voice input"
          style={{width:36, height:36, borderRadius:8, border:"1px solid #DDE1EE",
            background:listening?"#FEE2E2":"#F7F8FC", cursor:"pointer", fontSize:16,
            display:"flex", alignItems:"center", justifyContent:"center"}}>
          {listening ? "🔴" : "🎤"}
        </button>
        <button onClick={()=>sendMessage(input)} disabled={!input.trim()||loading}
          style={{width:36, height:36, borderRadius:8, border:"none",
            background:input.trim()&&!loading?"#1B3FAB":"#93A5D4",
            cursor:input.trim()&&!loading?"pointer":"not-allowed",
            color:"#fff", fontSize:16, display:"flex", alignItems:"center", justifyContent:"center"}}>
          ➤
        </button>
      </div>
    </div>
  );
}

function QuantumSimulator({result}) {
  const [phase, setPhase] = useState("idle"); // idle | running | done
  const [step, setStep]   = useState(0);
  const [progress, setProgress] = useState(0);
  const intervalRef = useRef(null);

  const cert = result?.certificate || {};
  const tls  = result?.tls_info || {};
  const pqc  = result?.pqc_assessment || {};
  const keyType = cert.key_type || "RSA";
  const keyBits = cert.key_bits || 2048;
  const isVulnerable = !["ML-DSA","SLH-DSA"].includes(keyType);

  const classicalYears = keyBits >= 4096 ? "300 billion years" : keyBits >= 2048 ? "13.7 billion years" : "years";
  const quantumTime    = keyBits >= 4096 ? "~14 hours" : keyBits >= 2048 ? "~8 hours" : "~2 hours";
  const qubitsNeeded   = Math.round(keyBits * 2.5);

  const steps = [
    {label:"INITIALISING QUANTUM SIMULATION", detail:"Loading lattice-based attack model...", color:"#6B7280"},
    {label:"TARGET IDENTIFIED", detail:`${result?.target} — ${keyType}-${keyBits} certificate`, color:"#1B3FAB"},
    {label:"HARVESTING PUBLIC KEY", detail:`Extracting ${keyBits}-bit public key from X.509 certificate...`, color:"#D97706"},
    {label:"INITIALISING SHOR'S ALGORITHM", detail:`Requires ${qubitsNeeded.toLocaleString()} logical qubits (2031-era quantum computer)`, color:"#EA580C"},
    {label:"COMPUTING QUANTUM FOURIER TRANSFORM", detail:"Period-finding on the RSA modulus N = p × q...", color:"#EA580C"},
    {label:"FACTORING RSA MODULUS", detail:`N = ${keyBits}-bit composite — finding prime factors p and q...`, color:"#DC2626"},
    {label:"PRIVATE KEY RECOVERED", detail:`${keyType}-${keyBits} private key derived in ${quantumTime}`, color:"#B91C1C"},
    {label:"DECRYPTING HISTORICAL SESSIONS", detail:"Accessing all TLS sessions recorded since 2019...", color:"#B91C1C"},
    {label:"ATTACK COMPLETE", detail:`${isVulnerable ? "⚠ KEY BROKEN — All encrypted data exposed" : "✓ PQC algorithms resisted quantum attack"}`, color: isVulnerable ? "#DC2626" : "#059669"},
  ];

  const run = () => {
    if(phase === "running") return;
    setPhase("running"); setStep(0); setProgress(0);
    let s = 0;
    intervalRef.current = setInterval(() => {
      s++;
      setStep(s);
      setProgress(Math.min(100, Math.round((s / steps.length) * 100)));
      if(s >= steps.length) {
        clearInterval(intervalRef.current);
        setPhase("done");
      }
    }, 600);
  };

  const reset = () => {
    clearInterval(intervalRef.current);
    setPhase("idle"); setStep(0); setProgress(0);
  };

  const score = pqc.score || 0;
  const riskColor = score < 40 ? "#DC2626" : score < 65 ? "#EA580C" : "#16A34A";

  return (
    <div>
      <div style={{background:"#FEF2F2",border:`1px solid ${riskColor}40`,borderRadius:10,padding:"16px",marginBottom:14}}>
        <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:12}}>
          <div style={{width:32,height:32,background:`${riskColor}22`,border:`1px solid ${riskColor}`,borderRadius:8,
            display:"flex",alignItems:"center",justifyContent:"center",fontSize:16}}>⚡</div>
          <div>
            <div style={{color:"#1A1D2E",fontWeight:700,fontSize:14}}>Quantum Attack Simulator</div>
            <div style={{color:"#9CA3AF",fontSize:11}}>Simulates Shor's Algorithm on {result?.target}</div>
          </div>
          <div style={{marginLeft:"auto"}}>
            <div style={{color:riskColor,fontFamily:"inherit",fontSize:20,fontWeight:900}}>{score}/100</div>
          </div>
        </div>

        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:10,marginBottom:14}}>
          {[
            ["TARGET KEY", `${keyType}-${keyBits}`, "#EF4444"],
            ["CLASSICAL BREAK TIME", classicalYears, "#059669"],
            ["QUANTUM BREAK TIME", quantumTime, "#DC2626"],
            ["QUBITS NEEDED", qubitsNeeded.toLocaleString(), "#8c9eff"],
            ["ATTACK", "Shor's Algorithm", "#D97706"],
            ["HNDL STATUS", isVulnerable ? "⚠ EXPOSED" : "✓ PROTECTED", isVulnerable ? "#DC2626" : "#059669"],
          ].map(([k,v,c])=>(
            <div key={k} style={{background:"#F7F8FC",border:"1px solid #DDE1EE",borderRadius:6,padding:"8px 10px"}}>
              <div style={{color:"#555555",fontSize:9,letterSpacing:1,marginBottom:3}}>{k}</div>
              <div style={{color:c,fontFamily:"inherit",fontSize:11,fontWeight:700}}>{v}</div>
            </div>
          ))}
        </div>

        <div style={{display:"flex",gap:8}}>
          <button onClick={run} disabled={phase==="running"} style={{
            flex:1,padding:"11px",borderRadius:7,cursor:phase==="running"?"not-allowed":"pointer",
            background:phase==="running"?"#1a0000":isVulnerable?"linear-gradient(135deg,#c0392b,#e74c3c)":"linear-gradient(135deg,#1e8449,#27ae60)",
            border:"none",color:"#fff",fontFamily:"inherit",fontSize:12,fontWeight:700,letterSpacing:1,
            boxShadow:phase==="running"?"none":`0 0 20px ${isVulnerable?"#ff174450":"#00e67650"}`}}>
            {phase==="running"?"⚡ ATTACK IN PROGRESS...":phase==="done"?"↻ RE-RUN SIMULATION":"⚡ LAUNCH QUANTUM ATTACK"}
          </button>
          {phase!=="idle"&&(
            <button onClick={reset} style={{padding:"11px 16px",borderRadius:7,cursor:"pointer",
              background:"#F0F2F8",border:"1px solid #DDE1EE",color:"#9CA3AF",fontFamily:"inherit",fontSize:11}}>
              RESET
            </button>
          )}
        </div>
      </div>

      {phase !== "idle" && (
        <div style={{background:"#F7F8FC",border:"1px solid #DDE1EE",borderRadius:10,padding:"16px",fontFamily:"inherit"}}>
          <div style={{display:"flex",justifyContent:"space-between",marginBottom:10}}>
            <span style={{color:"#555",fontSize:11}}>SIMULATION PROGRESS</span>
            <span style={{color:riskColor,fontWeight:700,fontSize:13}}>{progress}%</span>
          </div>
          <div style={{background:"#E2E8F0",borderRadius:3,height:4,marginBottom:14,overflow:"hidden"}}>
            <div style={{height:"100%",width:`${progress}%`,background:`linear-gradient(90deg,#7c3aed,${riskColor})`,
              transition:"width 0.5s ease",borderRadius:3}}/>
          </div>

          <div style={{maxHeight:280,overflowY:"auto"}}>
            {steps.slice(0, step).map((s, i) => (
              <div key={i} style={{display:"flex",gap:10,padding:"6px 0",
                borderBottom:"1px solid #EEF0F8",alignItems:"flex-start"}}>
                <span style={{color:"#6B7280",fontSize:10,flexShrink:0,marginTop:2}}>{String(i+1).padStart(2,"0")}</span>
                <div>
                  <div style={{color:s.color,fontSize:11,fontWeight:700}}>{s.label}</div>
                  <div style={{color:"#4B5563",fontSize:10,marginTop:2}}>{s.detail}</div>
                </div>
                <span style={{marginLeft:"auto",color:"#6B7280",fontSize:10,flexShrink:0}}>✓</span>
              </div>
            ))}
            {phase==="running" && step < steps.length && (
              <div style={{display:"flex",gap:10,padding:"6px 0",alignItems:"center"}}>
                <span style={{color:"#7C3AED",fontSize:10,flexShrink:0}}>{String(step+1).padStart(2,"0")}</span>
                <div style={{color:"#1B3FAB",fontSize:11}}>{steps[step]?.label}</div>
                <span style={{marginLeft:"auto",color:"#7C3AED",animation:"none"}}>▶</span>
              </div>
            )}
          </div>

          {phase === "done" && (
            <div style={{marginTop:14,padding:"14px",borderRadius:8,
              background:isVulnerable?"#FEF2F2":"#ECFDF5",
              border:`1px solid ${isVulnerable?"#DC2626":"#059669"}40`}}>
              <div style={{color:isVulnerable?"#DC2626":"#059669",fontWeight:900,fontSize:16,marginBottom:6}}>
                {isVulnerable?"🔴 ATTACK SUCCESSFUL — KEY COMPROMISED":"🟢 ATTACK FAILED — PQC ALGORITHMS HELD"}
              </div>
              {isVulnerable ? (
                <>
                  <div style={{color:"#DC2626",fontSize:12,marginBottom:4}}>
                    {keyType}-{keyBits} private key recovered in {quantumTime} using {qubitsNeeded.toLocaleString()} qubits
                  </div>
                  <div style={{color:"#7F1D1D",fontSize:11}}>
                    All TLS sessions encrypted with this key are now decryptable. Estimated data exposed: all HTTPS traffic
                    since certificate issuance. This is the Harvest Now, Decrypt Later threat materialised.
                  </div>
                  <div style={{color:"#EA580C",fontSize:11,marginTop:8,fontWeight:700}}>
                    → IMMEDIATE ACTION: Migrate to ML-DSA-65 (FIPS 204) + ML-KEM-768 (FIPS 203)
                  </div>
                </>
              ) : (
                <div style={{color:"#065F46",fontSize:12}}>
                  ML-DSA / ML-KEM algorithms are based on Module Learning With Errors (MLWE) — a mathematical problem
                  believed to be hard for both classical and quantum computers. Shor's algorithm does not apply.
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function DetailPanel({result, backendUrl, token}) {
  const [tab,setTab]=useState("overview");
  useEffect(()=>setTab("overview"),[result?.target]);
  if(!result) return (
    <div style={{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",height:"100%",color:"#E5E7EB"}}>
      <div style={{fontSize:64,marginBottom:16}}>⚛</div>
      <div style={{fontSize:15,letterSpacing:4,color:"#9CA3AF"}}>SELECT A TARGET</div>
      <div style={{fontSize:12,color:"#D1D5DB",marginTop:8}}>TO VIEW FULL ANALYSIS</div>
    </div>
  );
  const pqc=result.pqc_assessment||{};const tls=result.tls_info||{};const cert=result.certificate||{};
  const cbom=result.cbom||{};const vulns=result.vulnerabilities||[];const dns=result.dns||{};
  const http=result.http_headers||{};const c=RISK_COLOR[pqc.status]||RISK_COLOR.UNKNOWN;
  const tabs=[
    {id:"overview",label:"Overview"},
    {id:"cbom",label:"CBOM"},
    {id:"certificate",label:"Certificate"},
    {id:"vulns",label:`Vulns${vulns.length>0?` (${vulns.length})`:""}`,alert:vulns.some(v=>v.severity==="CRITICAL")},
    {id:"dns",label:"DNS"},{id:"headers",label:"Headers"},
    {id:"ai",label:"🤖 AI",glow:true},
    {id:"quantum",label:"⚡ Attack Sim",glow:true},
    {id:"roadmap",label:"Roadmap"},
  ];
  return (
    <div style={{height:"100%",display:"flex",flexDirection:"column"}}>
      <div style={{padding:"16px 20px",borderBottom:"1px solid #DDE1EE",background:c.bg}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
          <div>
            <div style={{color:"#1A1D2E",fontFamily:"inherit",fontWeight:800,fontSize:16}}>🔒 {result.target}</div>
            <div style={{color:"#6B7280",fontSize:11,marginTop:3}}>{tls.tls_version||"—"} · Port {result.port} · {tls.cipher_grade?<GradeBadge grade={tls.cipher_grade}/>:""}</div>
            <div style={{marginTop:6,display:"flex",gap:6,flexWrap:"wrap"}}>
              {tls.forward_secrecy&&<span style={{background:"#00e67610",border:"1px solid #00e67640",color:"#059669",padding:"1px 7px",borderRadius:3,fontSize:10}}>FS</span>}
              {result.status==="success_legacy"&&<span style={{background:"#FFF7ED",border:"1px solid #FED7AA",color:"#EA580C",padding:"1px 7px",borderRadius:3,fontSize:10}}>LEGACY CIPHER</span>}
              {result.status==="success_unverified"&&<span style={{background:"#ff525210",border:"1px solid #ff525240",color:"#DC2626",padding:"1px 7px",borderRadius:3,fontSize:10}}>UNVERIFIED CERT</span>}
              {result.demo&&<span style={{background:"#EFF6FF",border:"1px solid #BFDBFE",color:"#2563EB",padding:"1px 7px",borderRadius:3,fontSize:10}}>DEMO DATA</span>}
            </div>
          </div>
          <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:6}}>
            <ScoreRing score={pqc.score||0} size={72}/>
            <Badge status={pqc.status}/>
            <div style={{color:"#9CA3AF",fontSize:10}}>{pqc.parameters_checked||40} params checked</div>
          </div>
        </div>
      </div>
      <div style={{display:"flex",borderBottom:"1px solid #DDE1EE",padding:"0 20px",overflowX:"auto"}}>
        {tabs.map(t=>(
          <button key={t.id} onClick={()=>setTab(t.id)} style={{background:"none",border:"none",
            color:tab===t.id?"#a78bfa":t.glow?"#9b59b6":"#666688",padding:"10px 12px",cursor:"pointer",
            fontFamily:"inherit",fontSize:11,borderBottom:tab===t.id?"2px solid #a78bfa":t.glow?"2px solid #7c3aed44":"2px solid transparent",
            whiteSpace:"nowrap",position:"relative",
            textShadow:t.glow&&tab!==t.id?"0 0 10px #9b59b6":"none"}}>
            {t.label}
            {t.alert&&<span style={{position:"absolute",top:6,right:4,width:6,height:6,borderRadius:"50%",background:"#DC2626"}}/>}
          </button>
        ))}
      </div>
      <div style={{flex:1,overflowY:"auto",padding:"16px 20px"}}>
        {tab==="overview"&&(
          <div>
            {/* Active PQC key-exchange detection banner */}
            {(() => {
              const det = tls.pqc_kex_detection || {};
              const isPqc = det.is_pqc;
              const ok = det.tls13_supported && !det.error;
              const bg = isPqc ? "#ECFDF5" : ok ? "#FFF7ED" : "#EFF6FF";
              const bd = isPqc ? "#A7F3D0" : ok ? "#FED7AA" : "#BFDBFE";
              const tc = isPqc ? "#065F46" : ok ? "#7C2D12" : "#1E3A8A";
              return (
                <div style={{background:bg,border:`1px solid ${bd}`,borderRadius:8,
                  padding:"8px 12px",marginBottom:14,fontSize:11,color:tc,display:"flex",gap:8}}>
                  <span>{isPqc ? "🛡️" : ok ? "⚠️" : "ℹ️"}</span>
                  <span>
                    <b>Active PQC key-exchange probe:</b>{" "}
                    {det.summary
                      ? det.summary
                      : "QuantumShield runs a raw TLS 1.3 handshake (empty key_share → HelloRetryRequest) to read the negotiated named group directly from the wire — detecting ML-KEM/Kyber that ssl.cipher() cannot see. No OQS/Wireshark needed."}
                  </span>
                </div>
              );
            })()}
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:16}}>
              {[
                ["TLS Version",tls.tls_version||"—",tls.tls_version?.includes("1.3")?"#059669":"#D97706"],
                ["Cipher Suite",tls.cipher_suite||"—","#8c9eff"],
                ["Key Exchange",tls.key_exchange||"—",(tls.pqc_kex_detection?.is_pqc||tls.key_exchange?.includes("Quantum-Safe")||tls.key_exchange?.includes("Hybrid PQC"))?"#059669":"#EF4444"],
                ["PQC KEX (detected)",tls.pqc_kex_detection?.selected_group||(tls.pqc_kex_detection?.error?"not detectable":"—"),tls.pqc_kex_detection?.is_pqc?"#059669":"#EF4444"],
                ["Cert Type",`${cert.key_type||"?"}-${cert.key_bits||0}`,cert.pqc_cert?"#059669":"#EF4444"],
                ["Forward Secrecy",tls.forward_secrecy?"✓ Enabled":"✗ Disabled",tls.forward_secrecy?"#059669":"#EF4444"],
                ["Cipher Grade",tls.cipher_grade||"?",{A:"#059669",B:"#16A34A",C:"#D97706",D:"#EF4444",F:"#DC2626"}[tls.cipher_grade]||"#888"],
                ["Cert Expires",cert.days_until_expiry!=null?`${cert.days_until_expiry} days`:"—",cert.days_until_expiry<30?"#EF4444":cert.days_until_expiry<90?"#D97706":"#059669"],
                ["CT Logs",cert.ct_sct_count>0?`✓ ${cert.ct_sct_count} SCTs`:"✗ None",cert.ct_sct_count>0?"#059669":"#D97706"],
              ].map(([l,v,c])=>(
                <div key={l} style={{background:"#FFFFFF",border:"1px solid #DDE1EE",borderRadius:7,padding:"10px 14px"}}>
                  <div style={{color:"#9CA3AF",fontSize:10,letterSpacing:1,marginBottom:5}}>{l.toUpperCase()}</div>
                  <div style={{color:c,fontFamily:"inherit",fontSize:12,fontWeight:600,wordBreak:"break-all"}}>{v}</div>
                </div>
              ))}
            </div>
            <div style={{color:"#4B5563",fontSize:10,fontWeight:700,letterSpacing:2,marginBottom:10}}>SECURITY FINDINGS</div>
            {pqc.positives?.map((p,i)=>(
              <div key={i} style={{display:"flex",gap:8,padding:"7px 0",borderBottom:"1px solid #DCFCE7",alignItems:"flex-start"}}>
                <span style={{color:"#059669",fontSize:14,flexShrink:0}}>✓</span>
                <span style={{color:"#065F46",fontSize:12}}>{p}</span>
              </div>
            ))}
            <div style={{marginTop:pqc.positives?.length?12:0}}>
              {pqc.issues?.map((issue,i)=>(
                <div key={i} style={{background:"#FEF2F2",border:`1px solid ${SEV_COLOR[issue.severity]||"#333"}30`,
                  borderLeft:`3px solid ${SEV_COLOR[issue.severity]||"#333"}`,borderRadius:6,padding:"9px 12px",marginBottom:7}}>
                  <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4,flexWrap:"wrap"}}>
                    <SevBadge sev={issue.severity}/><span style={{color:"#7F1D1D",fontSize:12}}>{issue.issue}</span>
                  </div>
                  <div style={{color:"#888",fontSize:11}}>→ {issue.action}</div>
                </div>
              ))}
            </div>
          </div>
        )}
        {tab==="cbom"&&(
          <div>
            <div style={{color:"#4B5563",fontSize:11,marginBottom:12,lineHeight:1.6}}>
              Cryptographic Bill of Materials · CycloneDX v1.4 · NIST SP 800-235
              <span style={{background:"#a78bfa22",color:"#1B3FAB",border:"1px solid #a78bfa44",padding:"1px 8px",borderRadius:4,fontSize:10,marginLeft:8,fontFamily:"inherit"}}>cyclonedx.org/schema/bom-1.4</span>
            </div>
            <CBOMTable components={cbom.components}/>
            {tls.supported_ciphers?.length>0&&(
              <div style={{marginTop:16}}>
                <div style={{color:"#9CA3AF",fontSize:10,letterSpacing:1,marginBottom:8}}>ALL SUPPORTED CIPHER SUITES</div>
                <div style={{display:"flex",flexWrap:"wrap",gap:5}}>
                  {tls.supported_ciphers.map((c,i)=>(
                    <span key={i} style={{background:"#F7F8FC",border:"1px solid #DDE1EE",color:"#6B7280",
                      padding:"3px 8px",borderRadius:4,fontSize:10,fontFamily:"inherit"}}>{c}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {tab==="certificate"&&(
          <div>
            {cert.issues?.map((issue,i)=>(
              <div key={i} style={{background:"#FEF2F2",border:`1px solid ${SEV_COLOR[issue.severity]}30`,
                borderLeft:`3px solid ${SEV_COLOR[issue.severity]}`,borderRadius:6,padding:"8px 12px",marginBottom:8}}>
                <SevBadge sev={issue.severity}/> <span style={{color:"#7F1D1D",fontSize:12,marginLeft:8}}>{issue.issue}</span>
                <div style={{color:"#888",fontSize:11,marginTop:4}}>→ {issue.action}</div>
              </div>
            ))}
            {[["Subject",cert.subject],["Issuer",cert.issuer],
              ["Key Type",`${cert.key_type}-${cert.key_bits}${cert.curve_name?` (${cert.curve_name})`:""}`],
              ["Signature Algo",cert.signature_algorithm],["Valid From",cert.not_before],["Valid Until",cert.not_after],
              ["Days Until Expiry",cert.days_until_expiry!=null?`${cert.days_until_expiry} days`:"—"],
              ["Self-Signed",cert.is_self_signed?"⚠ YES":"No"],
              ["CT SCT Count",cert.ct_sct_count!=null?`${cert.ct_sct_count} SCTs`:"—"],
              ["PQC Certificate",cert.pqc_cert?"✓ YES — Quantum Safe":"✗ NO — Quantum Vulnerable"],
              ["OCSP URL",cert.ocsp_urls?.[0]||"None"],
            ].map(([l,v])=>v&&(
              <div key={l} style={{display:"flex",borderBottom:"1px solid #EEF0F8",padding:"9px 0"}}>
                <div style={{width:160,color:"#9CA3AF",fontSize:11,flexShrink:0}}>{l}</div>
                <div style={{color:"#374151",fontSize:12,fontFamily:"inherit",wordBreak:"break-all"}}>{v||"—"}</div>
              </div>
            ))}
            {cert.sans?.length>0&&(
              <div style={{marginTop:14}}>
                <div style={{color:"#9CA3AF",fontSize:10,letterSpacing:1,marginBottom:8}}>SUBJECT ALTERNATIVE NAMES ({cert.sans.length})</div>
                <div style={{display:"flex",flexWrap:"wrap",gap:5}}>
                  {cert.sans.map((san,i)=>(
                    <span key={i} style={{background:"#F0F2F8",border:"1px solid #DDE1EE",color:"#2563EB",
                      padding:"2px 9px",borderRadius:4,fontSize:11,fontFamily:"inherit"}}>{san}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {tab==="vulns"&&<div><div style={{color:"#4B5563",fontSize:11,marginBottom:12}}>Cross-referenced against known TLS/cryptographic vulnerability database</div><VulnPanel vulns={vulns}/></div>}
        {tab==="dns"&&<div><div style={{color:"#4B5563",fontSize:11,marginBottom:12}}>DNS security configuration analysis</div><DNSPanel dns={dns}/></div>}
        {tab==="headers"&&<div><div style={{color:"#4B5563",fontSize:11,marginBottom:12}}>HTTP security headers affecting cryptographic posture</div><HeadersPanel http={http}/></div>}
        {tab==="ai"&&(
          <div>
            <div style={{color:"#4B5563",fontSize:11,marginBottom:12,lineHeight:1.6}}>
              AI-powered plain-language explanation of scan results · Powered by Google Gemini AI
            </div>
            <AIPanel result={result} backendUrl={backendUrl} token={token}/>
          </div>
        )}
        {tab==="quantum"&&(
          <div>
            <div style={{color:"#4B5563",fontSize:11,marginBottom:12,lineHeight:1.6}}>
              Simulates Shor's Algorithm attack on this target's cryptographic configuration
            </div>
            <QuantumSimulator result={result}/>
          </div>
        )}
        {tab==="roadmap"&&(
          <div>
            <div style={{background:"#ECFDF5",border:"1px solid #00e67620",borderRadius:8,padding:"14px 16px",marginBottom:14}}>
              <div style={{color:"#059669",fontWeight:700,fontSize:13,marginBottom:12}}>🗺 NIST PQC Migration Roadmap for {result.target}</div>
              {[
                {phase:"Phase 1 — Immediate (0–3 months)",color:"#DC2626",items:["Audit and inventory ALL cryptographic assets (CBOM)","Disable TLS 1.0 and TLS 1.1 on all endpoints","Replace RC4, 3DES, DES, NULL ciphers with AES-256-GCM","Enforce TLS 1.3 as minimum protocol version","Enable HSTS with max-age=31536000, includeSubDomains, preload"]},
                {phase:"Phase 2 — Short-term (3–12 months)",color:"#D97706",items:["Deploy hybrid key exchange: X25519 + ML-KEM-768 (FIPS 203)","Begin PKI migration planning for ML-DSA (FIPS 204) certificates","Implement crypto-agility framework for rapid algorithm swaps","Add CAA DNS records restricting certificate issuance"]},
                {phase:"Phase 3 — Long-term (1–3 years)",color:"#15803D",items:["Full certificate migration to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)","Deploy ML-KEM-1024 for highest-security endpoints","Establish continuous CBOM lifecycle management","Obtain 'Fully Quantum Safe' certification for all public assets"]},
              ].map(({phase,color,items})=>(
                <div key={phase} style={{marginBottom:16}}>
                  <div style={{color,fontSize:11,fontWeight:700,letterSpacing:1,marginBottom:8,padding:"4px 10px",background:`${color}15`,borderRadius:4,display:"inline-block"}}>{phase.toUpperCase()}</div>
                  {items.map((item,i)=>(
                    <div key={i} style={{color:"#374151",fontSize:12,padding:"4px 0 4px 14px",borderLeft:`2px solid ${color}30`,marginBottom:3}}>→ {item}</div>
                  ))}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ResultCard({result,onSelect,selected}) {
  const pqc=result.pqc_assessment||{};const tls=result.tls_info||{};
  const vulnCount=result.vulnerabilities?.length||0;const c=RISK_COLOR[pqc.status]||RISK_COLOR.UNKNOWN;
  return (
    <div onClick={()=>onSelect(result)} style={{background:selected?"#F3F4F6":"#FFFFFF",
      border:`1px solid ${selected?c.border:"#DDE1EE"}`,borderLeft:`3px solid ${c.border}`,
      borderRadius:8,padding:"12px 14px",cursor:"pointer",transition:"all 0.2s",marginBottom:8,
      boxShadow:selected?`0 0 16px ${c.glow}`:"none"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <div style={{flex:1,minWidth:0}}>
          <div style={{color:"#1A1D2E",fontWeight:700,fontFamily:"inherit",fontSize:13,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>🔒 {result.target}</div>
          <div style={{color:"#9CA3AF",fontSize:11,marginTop:3}}>
            {tls.tls_version||"—"} · {tls.cipher_grade?`Grade ${tls.cipher_grade}`:""}
            {vulnCount>0&&<span style={{color:"#DC2626",marginLeft:6}}>⚠ {vulnCount} vuln{vulnCount>1?"s":""}</span>}
          </div>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:8,flexShrink:0}}>
          <ScoreRing score={pqc.score||0} size={48}/>
          <Badge status={pqc.status} small/>
        </div>
      </div>
    </div>
  );
}

// ── API Scanner Panel ─────────────────────────────────────────────────────────
function APIScanPanel({backendUrl, token}) {
  const [url, setUrl]         = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState(null);
  const [error, setError]     = useState("");
  const [pollMsg, setPollMsg] = useState("");

  const scan = async () => {
    if(!url.trim()) return;
    setLoading(true); setResult(null); setError(""); setPollMsg("");
    const headers = {"Content-Type":"application/json"};
    if(token) headers["Authorization"]=`Bearer ${token}`;
    try {
      // Step 1: submit job
      const res = await fetch(`${backendUrl}/api/v1/scan/api`, {
        method:"POST", headers,
        body: JSON.stringify({base_url: url.trim(), port:443}),
        signal: AbortSignal.timeout(15000)
      });
      if(!res.ok){ setError(`Scan failed: ${res.status}`); setLoading(false); return; }
      const {job_id} = await res.json();
      // Step 2: poll for results (max 60s)
      setPollMsg("Scanning API endpoints...");
      for(let i=0; i<30; i++){
        await new Promise(r=>setTimeout(r,2000));
        try {
          const poll = await fetch(`${backendUrl}/api/v1/scan/api/job/${job_id}`,
            {headers, signal:AbortSignal.timeout(5000)});
          if(poll.ok){
            const job = await poll.json();
            if(job.status==="done"){ setResult(job.result); break; }
            if(job.status==="error"){ setError(job.error||"Scan error"); break; }
            setPollMsg(`Scanning... (${i*2}s)`);
          }
        } catch(_){}
      }
      if(!result && !error) setPollMsg("");
    } catch(e) { setError(`Error: ${e.message}`); }
    setLoading(false); setPollMsg("");
  };

  const statusColor = {QUANTUM_SAFE:"#059669",PQC_READY:"#16A34A",TRANSITIONING:"#EA580C",VULNERABLE:"#DC2626"};

  return (
    <div style={{padding:"24px 28px",overflowY:"auto",flex:1,minHeight:0}}>
      <div style={{marginBottom:20}}>
        <div style={{color:"#1A1D2E",fontWeight:800,fontSize:18,letterSpacing:2}}>🔌 API ENDPOINT SCANNER</div>
        <div style={{color:"#9CA3AF",fontSize:11,marginTop:3}}>Discovers API endpoints and scans TLS config per endpoint · CERT-In CBOM Annexure-A</div>
      </div>

      <div style={{display:"flex",gap:10,marginBottom:20}}>
        <input value={url} onChange={e=>setUrl(e.target.value)}
          onKeyDown={e=>e.key==="Enter"&&scan()}
          placeholder="https://api.pnbindia.in or pnbindia.in"
          style={{flex:1,background:"#F7F8FC",border:"1px solid #DDE1EE",borderRadius:7,
            color:"#1A1D2E",fontFamily:"inherit",fontSize:13,padding:"11px 14px",outline:"none"}}/>
        <button onClick={scan} disabled={loading} style={{
          padding:"11px 24px",borderRadius:7,border:"none",cursor:loading?"not-allowed":"pointer",
          background:loading?"#1a1a3a":"linear-gradient(135deg,#7c3aed,#2563eb)",
          color:"#fff",fontFamily:"inherit",fontSize:12,fontWeight:700,
          boxShadow:loading?"none":"0 0 20px #7c3aed40"}}>
          {loading ? (pollMsg || "🔍 Scanning...") : "🔍 Scan API Endpoints"}
        </button>
      </div>

      {error && <div style={{background:"#ff174415",border:"1px solid #ff174440",color:"#DC2626",
        padding:"10px 14px",borderRadius:8,marginBottom:16,fontSize:12}}>{error}</div>}

      {result && (
        <div>
          {/* Summary */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:20}}>
            {[
              ["ENDPOINTS PROBED", result.api_tls_summary?.total_endpoints_discovered||0, "#8c9eff"],
              ["REACHABLE", result.api_tls_summary?.total_reachable||0, "#16A34A"],
              ["TLS VERSIONS", (result.api_tls_summary?.tls_versions||[]).join(", ")||"—", "#D97706"],
              ["WORST GRADE", result.api_tls_summary?.worst_cipher_grade||"?",
                {A:"#059669",B:"#16A34A",C:"#D97706",D:"#EF4444",F:"#DC2626"}[result.api_tls_summary?.worst_cipher_grade]||"#888"],
            ].map(([l,v,c])=>(
              <div key={l} style={{background:"#FFFFFF",border:`1px solid ${c}20`,borderRadius:8,padding:"12px 14px"}}>
                <div style={{color:"#9CA3AF",fontSize:9,letterSpacing:2}}>{l}</div>
                <div style={{color:c,fontSize:18,fontWeight:900,fontFamily:"inherit",marginTop:4}}>{v}</div>
              </div>
            ))}
          </div>

          {/* PQC Issues */}
          {result.pqc_issues?.length>0 && (
            <div style={{marginBottom:16}}>
              <div style={{color:"#4B5563",fontSize:10,letterSpacing:2,marginBottom:10}}>PQC ISSUES DETECTED</div>
              {result.pqc_issues.map((issue,i)=>(
                <div key={i} style={{background:"#FEF2F2",border:`1px solid ${SEV_COLOR[issue.severity]||"#333"}30`,
                  borderLeft:`3px solid ${SEV_COLOR[issue.severity]||"#333"}`,borderRadius:6,padding:"10px 14px",marginBottom:8}}>
                  <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4}}>
                    <SevBadge sev={issue.severity}/>
                    <span style={{color:"#7F1D1D",fontSize:12}}>{issue.issue}</span>
                  </div>
                  <div style={{color:"#888",fontSize:11}}>→ {issue.action}</div>
                </div>
              ))}
            </div>
          )}

          {/* Reachable Endpoints Table */}
          {result.endpoints_reachable?.length>0 && (
            <div style={{marginBottom:16}}>
              <div style={{color:"#4B5563",fontSize:10,letterSpacing:2,marginBottom:10}}>
                REACHABLE API ENDPOINTS ({result.endpoints_reachable.length})
              </div>
              <div style={{overflowX:"auto"}}>
                <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
                  <thead><tr style={{borderBottom:"1px solid #DDE1EE"}}>
                    {["Path","Status","TLS","Cipher","Grade","FS","Quantum Safe","Content-Type"].map(h=>(
                      <th key={h} style={{padding:"7px 10px",textAlign:"left",color:"#9CA3AF",fontSize:10,letterSpacing:1,whiteSpace:"nowrap"}}>{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>
                    {result.endpoints_reachable.map((ep,i)=>(
                      <tr key={i} style={{borderBottom:"1px solid #EEF0F8"}}>
                        <td style={{padding:"8px 10px",color:"#1B3FAB",fontFamily:"inherit",fontSize:11}}>{ep.path}</td>
                        <td style={{padding:"8px 10px",color:ep.status_code<400?"#059669":"#D97706"}}>{ep.status_code||"—"}</td>
                        <td style={{padding:"8px 10px",color:ep.tls_version?.includes("1.3")?"#059669":"#D97706",whiteSpace:"nowrap"}}>{ep.tls_version||"—"}</td>
                        <td style={{padding:"8px 10px",color:"#6B7280",maxWidth:140,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{ep.cipher_suite||"—"}</td>
                        <td style={{padding:"8px 10px"}}>{ep.cipher_grade?<GradeBadge grade={ep.cipher_grade}/>:"—"}</td>
                        <td style={{padding:"8px 10px",color:ep.forward_secrecy?"#059669":"#EF4444"}}>{ep.forward_secrecy?"✓":"✗"}</td>
                        <td style={{padding:"8px 10px",color:ep.quantum_safe?"#059669":"#EF4444"}}>{ep.quantum_safe?"✓ YES":"✗ NO"}</td>
                        <td style={{padding:"8px 10px",color:"#9CA3AF",fontSize:10}}>{ep.content_type||"—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* CERT-In CBOM */}
          {result.cert_in_cbom?.length>0 && (
            <div>
              <div style={{color:"#4B5563",fontSize:10,letterSpacing:2,marginBottom:10}}>
                CERT-IN CBOM ANNEXURE-A — API LAYER ({result.cert_in_cbom.length} components)
              </div>
              <div style={{background:"#FFFFFF",border:"1px solid #DDE1EE",borderRadius:8,padding:"12px",overflowX:"auto"}}>
                {result.cert_in_cbom.slice(0,10).map((c,i)=>(
                  <div key={i} style={{display:"flex",gap:12,padding:"7px 0",borderBottom:"1px solid #EEF0F8",fontSize:11,flexWrap:"wrap"}}>
                    <span style={{color:"#1B3FAB",minWidth:200,fontFamily:"inherit"}}>{c.endpoint?.split("/").slice(-2).join("/")}</span>
                    <span style={{color:"#6B7280"}}>{c.protocol}</span>
                    <span style={{color:"#9CA3AF"}}>{c.cipher_suite?.substring(0,25)}</span>
                    <span style={{color:c.quantum_safe?"#059669":"#EF4444",fontWeight:700}}>{c.quantum_safe?"QUANTUM SAFE":"QUANTUM VULNERABLE"}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.endpoints_reachable?.length===0 && (
            <div style={{textAlign:"center",padding:"40px",color:"#D1D5DB"}}>
              <div style={{fontSize:36,marginBottom:10}}>🔌</div>
              <div>No reachable API endpoints found at {result.target}</div>
              <div style={{fontSize:11,marginTop:6,color:"#E5E7EB"}}>Try entering a base URL like https://api.yourbank.com</div>
            </div>
          )}
        </div>
      )}

      {!result && !loading && (
        <div style={{textAlign:"center",padding:"60px 0",color:"#D1D5DB"}}>
          <div style={{fontSize:48,marginBottom:12}}>🔌</div>
          <div style={{fontSize:14,letterSpacing:2}}>API ENDPOINT DISCOVERY</div>
          <div style={{fontSize:11,marginTop:8,color:"#E5E7EB"}}>Enter a base URL to discover and scan all API endpoints</div>
          <div style={{marginTop:16,display:"flex",gap:8,justifyContent:"center",flexWrap:"wrap"}}>
            {["https://pnbindia.in","https://sbi.co.in","https://api.example.com"].map(u=>(
              <button key={u} onClick={()=>setUrl(u)} style={{
                background:"#F7F8FC",border:"1px solid #DDE1EE",color:"#9CA3AF",
                padding:"5px 12px",borderRadius:5,cursor:"pointer",fontFamily:"inherit",fontSize:11}}>
                {u}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── VPN Scanner Panel ─────────────────────────────────────────────────────────
function VPNScanPanel({backendUrl, token}) {
  const [host, setHost]       = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState(null);
  const [error, setError]     = useState("");
  const [pollMsg, setPollMsg] = useState("");

  const scan = async () => {
    if(!host.trim()) return;
    setLoading(true); setResult(null); setError(""); setPollMsg("");
    const headers = {"Content-Type":"application/json"};
    if(token) headers["Authorization"]=`Bearer ${token}`;
    const hostname = host.trim().replace(/^https?:\/\//,"").split("/")[0];
    try {
      // Step 1: submit job
      const res = await fetch(`${backendUrl}/api/v1/scan/vpn`, {
        method:"POST", headers,
        body: JSON.stringify({hostname}),
        signal: AbortSignal.timeout(15000)
      });
      if(!res.ok){ setError(`Scan failed: ${res.status}`); setLoading(false); return; }
      const {job_id} = await res.json();
      // Step 2: poll for results (max 60s)
      setPollMsg("Probing VPN ports...");
      for(let i=0; i<30; i++){
        await new Promise(r=>setTimeout(r,2000));
        try {
          const poll = await fetch(`${backendUrl}/api/v1/scan/vpn/job/${job_id}`,
            {headers, signal:AbortSignal.timeout(5000)});
          if(poll.ok){
            const job = await poll.json();
            if(job.status==="done"){ setResult(job.result); break; }
            if(job.status==="error"){ setError(job.error||"Probe error"); break; }
            setPollMsg(`Probing... (${i*2}s)`);
          }
        } catch(_){}
      }
    } catch(e) { setError(`Error: ${e.message}`); }
    setLoading(false); setPollMsg("");
  };

  const pqcColor = {QUANTUM_SAFE:"#059669",PQC_READY:"#D97706",TRANSITIONING:"#EA580C",VULNERABLE:"#DC2626",NOT_ASSESSED:"#6B7280"};
  const protoColor = {"TCP":"#2563EB","UDP":"#7C3AED"};

  return (
    <div style={{padding:"24px 28px",overflowY:"auto",flex:1,minHeight:0}}>
      <div style={{marginBottom:20}}>
        <div style={{color:"#1A1D2E",fontWeight:800,fontSize:18,letterSpacing:2}}>🛡️ TLS-BASED VPN SCANNER</div>
        <div style={{color:"#9CA3AF",fontSize:11,marginTop:3}}>Probes IKEv2, OpenVPN, SSL-VPN, WireGuard ports · Problem Statement: "TLS-based VPN" discovery</div>
      </div>

      <div style={{display:"flex",gap:10,marginBottom:20}}>
        <input value={host} onChange={e=>setHost(e.target.value)}
          onKeyDown={e=>e.key==="Enter"&&scan()}
          placeholder="pnbindia.in or 192.168.1.1"
          style={{flex:1,background:"#F7F8FC",border:"1px solid #DDE1EE",borderRadius:7,
            color:"#1A1D2E",fontFamily:"inherit",fontSize:13,padding:"11px 14px",outline:"none"}}/>
        <button onClick={scan} disabled={loading} style={{
          padding:"11px 24px",borderRadius:7,border:"none",cursor:loading?"not-allowed":"pointer",
          background:loading?"#1a1a3a":"linear-gradient(135deg,#0e6655,#1a5276)",
          color:"#fff",fontFamily:"inherit",fontSize:12,fontWeight:700,
          boxShadow:loading?"none":"0 0 20px #0e665540"}}>
          {loading ? (pollMsg || "🛡️ Probing...") : "🛡️ Probe VPN Ports"}
        </button>
      </div>

      {/* Port legend */}
      <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:16}}>
        {[["UDP/500","IKEv2"],["UDP/4500","IKEv2 NAT-T"],["UDP/1194","OpenVPN"],["TCP/1194","OpenVPN TCP"],
          ["TCP/443","SSL-VPN"],["UDP/51820","WireGuard"],["TCP/1723","PPTP"],["TCP/4433","SSL-VPN Alt"],].map(([p,n])=>(
          <span key={p} style={{background:"#F7F8FC",border:"1px solid #DDE1EE",color:"#9CA3AF",
            padding:"3px 8px",borderRadius:4,fontSize:10,fontFamily:"inherit"}}>{p} {n}</span>
        ))}
      </div>

      {error && <div style={{background:"#ff174415",border:"1px solid #ff174440",color:"#DC2626",
        padding:"10px 14px",borderRadius:8,marginBottom:16,fontSize:12}}>{error}</div>}

      {result && (
        <div>
          {/* Summary */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:20}}>
            {[
              ["PORTS PROBED", result.summary?.ports_open!==undefined?`${result.ports_probed} total`:"—", "#8c9eff"],
              ["OPEN PORTS", result.summary?.ports_open||0, result.summary?.ports_open>0?"#16A34A":"#3a5a3a"],
              ["TLS-VPN FOUND", result.summary?.tls_vpn_count||0, result.tls_vpn_found?"#D97706":"#3a5a3a"],
              ["PQC ISSUES", result.pqc_issues?.length||0, result.pqc_issues?.length>0?"#DC2626":"#059669"],
            ].map(([l,v,c])=>(
              <div key={l} style={{background:"#FFFFFF",border:`1px solid ${c}20`,borderRadius:8,padding:"12px 14px"}}>
                <div style={{color:"#9CA3AF",fontSize:9,letterSpacing:2}}>{l}</div>
                <div style={{color:c,fontSize:18,fontWeight:900,fontFamily:"inherit",marginTop:4}}>{v}</div>
              </div>
            ))}
          </div>

          {/* Open ports */}
          {result.open_ports?.length>0 && (
            <div style={{background:"#ECFDF5",border:"1px solid #00e67620",borderRadius:8,padding:"12px 16px",marginBottom:16}}>
              <div style={{color:"#059669",fontSize:11,fontWeight:700,marginBottom:8}}>OPEN PORTS DETECTED</div>
              <div style={{display:"flex",flexWrap:"wrap",gap:8}}>
                {result.open_ports.map((p,i)=>(
                  <span key={i} style={{background:"#00e67620",border:"1px solid #00e67640",color:"#059669",
                    padding:"3px 10px",borderRadius:4,fontSize:11,fontFamily:"inherit"}}>{p}</span>
                ))}
              </div>
            </div>
          )}

          {/* PQC Issues */}
          {result.pqc_issues?.length>0 && (
            <div style={{marginBottom:16}}>
              <div style={{color:"#4B5563",fontSize:10,letterSpacing:2,marginBottom:10}}>VPN PQC ISSUES</div>
              {result.pqc_issues.map((issue,i)=>(
                <div key={i} style={{background:"#FEF2F2",border:`1px solid ${SEV_COLOR[issue.severity]||"#333"}30`,
                  borderLeft:`3px solid ${SEV_COLOR[issue.severity]||"#333"}`,borderRadius:6,padding:"10px 14px",marginBottom:8}}>
                  <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4}}>
                    <SevBadge sev={issue.severity}/><span style={{color:"#7F1D1D",fontSize:12}}>{issue.issue}</span>
                  </div>
                  <div style={{color:"#888",fontSize:11}}>→ {issue.action}</div>
                </div>
              ))}
            </div>
          )}

          {/* Port-by-port results */}
          <div style={{color:"#4B5563",fontSize:10,letterSpacing:2,marginBottom:10}}>PORT PROBE RESULTS</div>
          <div style={{overflowX:"auto"}}>
            <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
              <thead><tr style={{borderBottom:"1px solid #DDE1EE"}}>
                {["Port","Proto","VPN Type","Status","TLS Version","Cipher","PQC Status"].map(h=>(
                  <th key={h} style={{padding:"7px 10px",textAlign:"left",color:"#9CA3AF",fontSize:10,letterSpacing:1}}>{h}</th>
                ))}
              </tr></thead>
              <tbody>
                {result.vpn_endpoints?.map((ep,i)=>(
                  <tr key={i} style={{borderBottom:"1px solid #EEF0F8",
                    opacity:ep.open?1:0.4}}>
                    <td style={{padding:"8px 10px",color:"#1A1D2E",fontFamily:"inherit",fontWeight:700}}>{ep.port}</td>
                    <td style={{padding:"8px 10px"}}>
                      <span style={{background:`${protoColor[ep.protocol]||"#888"}22`,color:protoColor[ep.protocol]||"#888",
                        padding:"1px 7px",borderRadius:3,fontSize:10,fontWeight:700}}>{ep.protocol}</span>
                    </td>
                    <td style={{padding:"8px 10px",color:"#374151"}}>{ep.vpn_type}</td>
                    <td style={{padding:"8px 10px",color:ep.open?"#059669":"#3a3a5a",fontWeight:700}}>{ep.open?"● OPEN":"○ CLOSED"}</td>
                    <td style={{padding:"8px 10px",color:ep.tls_version?.includes("1.3")?"#059669":"#D97706"}}>{ep.tls_version||"—"}</td>
                    <td style={{padding:"8px 10px",color:"#6B7280",maxWidth:120,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{ep.cipher_suite||"—"}</td>
                    <td style={{padding:"8px 10px"}}>
                      <span style={{color:pqcColor[ep.pqc_assessment]||"#888",fontSize:10,fontWeight:700}}>
                        {ep.pqc_assessment||"NOT_ASSESSED"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* CERT-In CBOM for VPN */}
          {result.cert_in_cbom?.length>0 && (
            <div style={{marginTop:16}}>
              <div style={{color:"#4B5563",fontSize:10,letterSpacing:2,marginBottom:8}}>
                CERT-IN CBOM — VPN LAYER ({result.cert_in_cbom.length} TLS-VPN components)
              </div>
              {result.cert_in_cbom.map((c,i)=>(
                <div key={i} style={{background:"#FFFFFF",border:"1px solid #DDE1EE",borderRadius:6,
                  padding:"10px 14px",marginBottom:6,display:"flex",gap:12,flexWrap:"wrap",fontSize:11}}>
                  <span style={{color:"#1B3FAB",fontFamily:"inherit"}}>{c.endpoint}</span>
                  <span style={{color:"#6B7280"}}>{c.protocol}</span>
                  <span style={{color:"#9CA3AF"}}>{c.cipher_suite}</span>
                  <span style={{color:c.quantum_safe?"#059669":"#EF4444",fontWeight:700}}>
                    {c.quantum_safe?"QUANTUM SAFE":"QUANTUM VULNERABLE"}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {!result && !loading && (
        <div style={{textAlign:"center",padding:"60px 0",color:"#D1D5DB"}}>
          <div style={{fontSize:48,marginBottom:12}}>🛡️</div>
          <div style={{fontSize:14,letterSpacing:2}}>VPN PORT DISCOVERY</div>
          <div style={{fontSize:11,marginTop:8,color:"#E5E7EB"}}>
            Probes {`{IKEv2, OpenVPN, SSL-VPN, WireGuard, PPTP, L2TP}`} on target hostname
          </div>
          <div style={{marginTop:16,display:"flex",gap:8,justifyContent:"center"}}>
            {["pnbindia.in","sbi.co.in","cloudflare.com"].map(h=>(
              <button key={h} onClick={()=>setHost(h)} style={{
                background:"#F7F8FC",border:"1px solid #DDE1EE",color:"#9CA3AF",
                padding:"5px 12px",borderRadius:5,cursor:"pointer",fontFamily:"inherit",fontSize:11}}>
                {h}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────────────────────
export default function QuantumShield() {
  const [token,      setToken]      = useState("");
  const [user,       setUser]       = useState(null);
  const [authReady,  setAuthReady]  = useState(false); // prevent flash before token check
  const [targets,    setTargets]    = useState("google.com\nexample.com\ncloudflare.com\nexpired.badssl.com\nrc4.badssl.com\n3des.badssl.com");
  const [results,    setResults]    = useState([]);
  const [scanning,   setScanning]   = useState(false);
  const [selected,   setSelected]   = useState(null);
  const [progress,   setProgress]   = useState({current:0,total:0,current_target:""});
  const [backendUrl, setBackendUrl] = useState(() => {
    try {
      return localStorage.getItem("qs_backend_url") || import.meta.env.VITE_BACKEND_URL || "http://localhost:8000";
    } catch (_) {
      return import.meta.env.VITE_BACKEND_URL || "http://localhost:8000";
    }
  });
  const handleBackendUrlChange = (url) => {
    setBackendUrl(url);
    try {
      localStorage.setItem("qs_backend_url", url);
    } catch (_) {}
  };
  const [backendOk,  setBackendOk]  = useState(false);
  const [activeView, setActiveView] = useState("scanner");
  const [termLog,    setTermLog]    = useState([]);
  const termRef = useRef(null);

  // On mount: validate any stored token. If valid, restore session. If not, force login.
  useEffect(()=>{
    const storedToken = localStorage.getItem("qs_token")||"";
    const storedUser  = (() => { try { return JSON.parse(localStorage.getItem("qs_user")||"null"); } catch { return null; } })();
    if(!storedToken || !storedUser) {
      // No stored session — show login
      localStorage.removeItem("qs_token"); localStorage.removeItem("qs_user");
      setAuthReady(true); return;
    }
    // Validate token with backend /me endpoint
    fetch(`${backendUrl}/api/v1/auth/me`, {
      headers:{"Authorization":`Bearer ${storedToken}`},
      signal: AbortSignal.timeout(4000)
    }).then(r => {
      if(r.ok) {
        // Token still valid — restore session
        setToken(storedToken); setUser(storedUser);
      } else {
        // Token expired or invalid — force login
        localStorage.removeItem("qs_token"); localStorage.removeItem("qs_user");
      }
      setAuthReady(true);
    }).catch(() => {
      // Backend unreachable — keep the stored session so a transient blip
      // (e.g. a cold-starting free-tier backend) doesn't force a re-login.
      if(storedToken && storedUser) {
        setToken(storedToken); setUser(storedUser);
      } else {
        localStorage.removeItem("qs_token"); localStorage.removeItem("qs_user");
      }
      setAuthReady(true);
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  },[]);

  // Check backend health — keeps polling so the LIVE/OFFLINE badge self-heals.
  // Render's free tier sleeps and can take ~50s to wake, so we poll quickly while
  // it's down (cold start) and slow down once it's up.
  useEffect(()=>{
    let cancelled=false; let timer;
    const check=async()=>{
      let ok=false;
      try{
        const r=await fetch(`${backendUrl}/api/v1/health`,{signal:AbortSignal.timeout(8000)});
        ok=r.ok;
      }catch(_){ ok=false; }
      if(cancelled) return;
      setBackendOk(ok);
      timer=setTimeout(check, ok?20000:4000);
    };
    check();
    return ()=>{cancelled=true; clearTimeout(timer);};
  },[backendUrl]);

  useEffect(()=>{if(termRef.current)termRef.current.scrollTop=termRef.current.scrollHeight;},[termLog]);

  const addLog=(msg,color="#8888cc")=>setTermLog(l=>[...l.slice(-60),{msg,color,t:new Date().toLocaleTimeString()}]);

  const handleLogin=(tk,u)=>{
    setToken(tk); setUser(u);
    localStorage.setItem("qs_token",tk);
    localStorage.setItem("qs_user",JSON.stringify(u));
  };
  const handleLogout=()=>{
    // Best-effort server-side token revocation, then clear local session.
    if(token){
      fetch(`${backendUrl}/api/v1/auth/logout`,{method:"POST",
        headers:{"Authorization":`Bearer ${token}`}}).catch(()=>{});
    }
    localStorage.removeItem("qs_token"); localStorage.removeItem("qs_user");
    setToken(""); setUser(null); setResults([]); setSelected(null); setTermLog([]);
  };

  const handleScan=async()=>{
    const list=targets.split("\n").map(t=>t.trim()).filter(Boolean);
    if(!list.length) return;
    setScanning(true);setResults([]);setSelected(null);setTermLog([]);
    addLog("QuantumShield — Deep PQC Scan initiated","#a78bfa");
    addLog(`Targets: ${list.length} | Parameters per target: 40+ | User: ${user?.username||"user"}`,"#6666aa");
    addLog("─".repeat(50),"#2a2a4a");
    setProgress({current:0,total:list.length,current_target:""});
    const newResults=[];
    for(let i=0;i<list.length;i++){
      const t=list[i];
      setProgress({current:i,total:list.length,current_target:t});
      addLog(`[${i+1}/${list.length}] Scanning ${t}...`,"#8888cc");
      addLog(`  → TLS handshake + certificate inspection`,"#4a4a6a");
      addLog(`  → DNS security analysis (CAA, DNSSEC, SPF, DMARC)`,"#4a4a6a");
      addLog(`  → Vulnerability database cross-reference`,"#4a4a6a");
      addLog(`  → PQC scoring (40 parameters)`,"#4a4a6a");
      const r=await performScan(t,backendUrl,token);
      newResults.push(r);setResults([...newResults]);
      if(r.status==="error"||r.status==="blocked"){
        addLog(`  ✗ ${t} — ${r.status.toUpperCase()}: ${r.error||(r.errors&&r.errors[0])||"scan failed"}`,"#DC2626");
        addLog(""," ");
        continue;
      }
      const score=r.pqc_assessment?.score||0;const status=r.pqc_assessment?.status||"UNKNOWN";
      const scoreColor=score>=75?"#059669":score>=50?"#16A34A":score>=35?"#EA580C":"#DC2626";
      addLog(`  ✓ ${t} — Score: ${score}/100 [${status}]${r.demo?" (DEMO DATA)":""}`,scoreColor);
      const vcount=r.vulnerabilities?.length||0;
      if(vcount>0)addLog(`  ⚠ ${vcount} vulnerability/vulnerabilities detected`,"#EF4444");
      addLog(""," ");
    }
    addLog("─".repeat(50),"#2a2a4a");
    const scored=newResults.filter(r=>r.status!=="error"&&r.status!=="blocked");
    const avgScore=scored.length?Math.round(scored.reduce((a,r)=>a+(r.pqc_assessment?.score||0),0)/scored.length):0;
    const failed=newResults.length-scored.length;
    addLog(`Scan complete. ${scored.length} scanned${failed?`, ${failed} failed/blocked`:""}.`,"#a78bfa");
    addLog(`Avg Score: ${avgScore}/100`,"#c0c0e0");
    setProgress(p=>({...p,current:list.length,current_target:""}));
    setScanning(false);
    if(newResults.length>0) setSelected(newResults[0]);
  };

  const exportCBOM=()=>{
    const report={
      report_metadata:{title:"QuantumShield CBOM Report",generated_at:new Date().toISOString(),
        scanner:"QuantumShield",nist_reference:["FIPS 203","FIPS 204","FIPS 205"],
        schema:"CycloneDX 1.4",parameters_checked:40,user:user?.username},
      executive_summary:{
        total_assets:results.length,
        quantum_safe:results.filter(r=>r.pqc_assessment?.status==="QUANTUM_SAFE").length,
        pqc_ready:results.filter(r=>r.pqc_assessment?.status==="PQC_READY").length,
        transitioning:results.filter(r=>r.pqc_assessment?.status==="TRANSITIONING").length,
        vulnerable:results.filter(r=>r.pqc_assessment?.status==="VULNERABLE").length,
        avg_score:results.length?Math.round(results.reduce((a,r)=>a+(r.pqc_assessment?.score||0),0)/results.length):0,
      },
      assets:results.map(r=>({
        asset:r.target,tls_version:r.tls_info?.tls_version,cipher_suite:r.tls_info?.cipher_suite,
        cipher_grade:r.tls_info?.cipher_grade,key_exchange:r.tls_info?.key_exchange,
        forward_secrecy:r.tls_info?.forward_secrecy,cert_type:`${r.certificate?.key_type}-${r.certificate?.key_bits}`,
        cert_expiry_days:r.certificate?.days_until_expiry,pqc_score:r.pqc_assessment?.score,
        pqc_status:r.pqc_assessment?.status,vulnerabilities:r.vulnerabilities,
        cbom_components:r.cbom?.components,dns_caa:r.dns?.caa_present,hsts:r.http_headers?.hsts?.present,
      }))
    };
    const blob=new Blob([JSON.stringify(report,null,2)],{type:"application/json"});
    const a=document.createElement("a");a.href=URL.createObjectURL(blob);
    a.download=`quantumshield-cbom-${Date.now()}.json`;a.click();
  };

  const exportPDF = async () => {
    const payload = {
      scan_title: "QuantumShield PQC Security Assessment",
      organization: user?.username ? `Scanned by: ${user.username}` : "QuantumShield Scanner",
      prepared_by: `QuantumShield — ${new Date().toLocaleDateString()}`,
      targets: results.map(r => ({
        target: r.target,
        pqc_score: r.pqc_assessment?.score || 0,
        pqc_status: r.pqc_assessment?.status || "UNKNOWN",
        tls_version: r.tls_info?.tls_version,
        cipher_suite: r.tls_info?.cipher_suite,
        key_exchange: r.tls_info?.key_exchange,
        cert_key_type: r.certificate?.key_type,
        cert_key_bits: r.certificate?.key_bits,
        forward_secrecy: r.tls_info?.forward_secrecy,
        days_until_expiry: r.certificate?.days_until_expiry,
        vulnerabilities: r.vulnerabilities || [],
        issues: r.pqc_assessment?.issues || [],
        positives: r.pqc_assessment?.positives || [],
      }))
    };
    try {
      const headers = {"Content-Type":"application/json"};
      if(token) headers["Authorization"] = `Bearer ${token}`;
      const res = await fetch(`${backendUrl}/api/v1/reports/pdf`, {
        method:"POST", headers, body: JSON.stringify(payload),
        signal: AbortSignal.timeout(30000)
      });
      if(res.ok) {
        const blob = await res.blob();
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `QuantumShield-Report-${Date.now()}.pdf`;
        a.click();
      } else {
        alert("PDF generation failed. Make sure reportlab is installed on the backend (add to requirements.txt).");
      }
    } catch(_) {
      alert("Cannot reach backend for PDF generation. Ensure backend is running.");
    }
  };

  const exportCSV = async () => {
    try {
      const headers = {"Content-Type":"application/json"};
      if(token) headers["Authorization"] = `Bearer ${token}`;
      const res = await fetch(`${backendUrl}/api/v1/export/csv`, {
        method:"POST", headers,
        body: JSON.stringify({results}),
        signal: AbortSignal.timeout(15000)
      });
      if(res.ok) {
        const blob = await res.blob();
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `QuantumShield-${Date.now()}.csv`;
        a.click();
      } else {
        // Fallback: generate CSV client-side
        const rows = [
          ["Target","Port","TLS Version","Cipher Suite","Cipher Grade","Forward Secrecy","Key Exchange","Cert Type","Cert Bits","Expiry Days","PQC Score","PQC Status","Vulnerabilities","Timestamp"],
          ...results.map(r => [
            r.target, r.port||443,
            r.tls_info?.tls_version||"",
            r.tls_info?.cipher_suite||"",
            r.tls_info?.cipher_grade||"",
            r.tls_info?.forward_secrecy?"Yes":"No",
            r.tls_info?.key_exchange||"",
            r.certificate?.key_type||"",
            r.certificate?.key_bits||"",
            r.certificate?.days_until_expiry||"",
            r.pqc_assessment?.score||"",
            r.pqc_assessment?.status||"",
            (r.vulnerabilities||[]).map(v=>v.name).join("|"),
            r.timestamp||""
          ])
        ];
        const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g,'""')}"`).join(",")).join("\n");
        const blob = new Blob([csv], {type:"text/csv"});
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `QuantumShield-${Date.now()}.csv`;
        a.click();
      }
    } catch(_) {
      // Pure client-side fallback
      const rows = [
        ["Target","TLS Version","Cipher Suite","PQC Score","PQC Status","Vulnerabilities"],
        ...results.map(r=>[r.target,r.tls_info?.tls_version||"",r.tls_info?.cipher_suite||"",r.pqc_assessment?.score||"",r.pqc_assessment?.status||"",(r.vulnerabilities||[]).map(v=>v.name).join("|")])
      ];
      const csv = rows.map(r=>r.join(",")).join("\n");
      const blob = new Blob([csv],{type:"text/csv"});
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `QuantumShield-${Date.now()}.csv`;
      a.click();
    }
  };

  const exportXML = async () => {
    try {
      const headers = {"Content-Type":"application/json"};
      if(token) headers["Authorization"] = `Bearer ${token}`;
      const res = await fetch(`${backendUrl}/api/v1/export/xml`, {
        method:"POST", headers,
        body: JSON.stringify({results}),
        signal: AbortSignal.timeout(15000)
      });
      if(res.ok) {
        const blob = await res.blob();
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `QuantumShield-${Date.now()}.xml`;
        a.click();
      } else {
        throw new Error("Backend XML failed");
      }
    } catch(_) {
      // Client-side XML fallback
      const ts = new Date().toISOString();
      const esc = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
      const lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        `<QuantumShieldReport generated="${ts}" schema="CERT-In-CBOM-v1.0">`,
        ...results.map(r=>[
          `  <Asset target="${esc(r.target)}" port="${r.port||443}">`,
          `    <TLS version="${esc(r.tls_info?.tls_version)}" cipher="${esc(r.tls_info?.cipher_suite)}" grade="${esc(r.tls_info?.cipher_grade)}" forward_secrecy="${r.tls_info?.forward_secrecy||false}"/>`,
          `    <Certificate type="${esc(r.certificate?.key_type)}" bits="${r.certificate?.key_bits||0}" quantum_safe="${r.certificate?.pqc_cert||false}"/>`,
          `    <PQCAssessment score="${r.pqc_assessment?.score||0}" status="${esc(r.pqc_assessment?.status)}"/>`,
          `    <Vulnerabilities count="${(r.vulnerabilities||[]).length}">`,
          ...(r.vulnerabilities||[]).map(v=>`      <Vulnerability name="${esc(v.name)}" cve="${esc(v.cve)}" severity="${esc(v.severity)}"/>`),
          `    </Vulnerabilities>`,
          `  </Asset>`,
        ].join("\n")),
        '</QuantumShieldReport>'
      ];
      const blob = new Blob([lines.join("\n")],{type:"application/xml"});
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `QuantumShield-${Date.now()}.xml`;
      a.click();
    }
  };

  const totalVulns=results.reduce((a,r)=>a+(r.vulnerabilities?.length||0),0);
  const roleColor={Admin:"#a78bfa",Operator:"#60a5fa",Checker:"#34d399"};

  // ── Not logged in ──────────────────────────────────────────────────────────
  if(!authReady) return (
    <div style={{background:"#F7F8FC",minHeight:"100vh",display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"inherit"}}>
      <div style={{textAlign:"center"}}>
        <div style={{fontSize:48,marginBottom:16,animation:"none"}}>⚛</div>
        <div style={{color:"#9CA3AF",fontSize:12,letterSpacing:3}}>INITIALISING...</div>
      </div>
    </div>
  );
  if(!token) return <LoginScreen backendUrl={backendUrl} onBackendUrlChange={handleBackendUrlChange} onLogin={handleLogin}/>;

  // ── Main App ───────────────────────────────────────────────────────────────
  const views=[
    {id:"scanner",   label:"⚡ Scanner"},
    {id:"api",       label:"🔌 API Scan"},
    {id:"vpn",       label:"🛡️ VPN Probe"},
    {id:"history",   label:"📋 History"},
    ...(user?.role==="Admin"?[{id:"users",label:"👥 Admin"}]:[]),
    {id:"algorithms",label:"⚛ NIST PQC"},
    {id:"about",     label:"ℹ About"},
  ];

  return (
    <div style={{background:"#F7F8FC",height:"100vh",fontFamily:"'Segoe UI',Arial,sans-serif",color:"#1A1D2E",overflow:"hidden",display:"flex",flexDirection:"column"}}>
      {/* Header */}
      <div style={{background:"#FFFFFF",borderBottom:"1px solid #DDE1EE",padding:"8px 20px",display:"flex",alignItems:"center",justifyContent:"space-between",minHeight:56,flexShrink:0,flexWrap:"wrap",gap:12,boxShadow:"0 1px 20px #7c3aed10",zIndex:10}}>
        <div style={{display:"flex",alignItems:"center",gap:12}}>
          <div style={{width:34,height:34,background:"linear-gradient(135deg,#7c3aed,#1d4ed8)",borderRadius:9,
            display:"flex",alignItems:"center",justifyContent:"center",fontSize:18,
            boxShadow:"0 0 16px #7c3aed50"}}>⚛</div>
          <div>
            <div style={{color:"#1A1D2E",fontWeight:900,fontSize:17,letterSpacing:3,
              textShadow:"0 0 20px #7c3aed40"}}>QUANTUMSHIELD</div>
            <div style={{color:"#9CA3AF",fontSize:9,letterSpacing:1}}>PQC SCANNER · NIST FIPS 203/204/205 · ACTIVE ML-KEM DETECTION</div>
          </div>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:10,flexWrap:"wrap",justifyContent:"flex-end",rowGap:8}}>
          <div style={{display:"flex",gap:2,flexWrap:"wrap",justifyContent:"flex-end"}}>
            {views.map(v=>(
              <button key={v.id} onClick={()=>setActiveView(v.id)} style={{
                background:activeView===v.id?"linear-gradient(135deg,#7c3aed,#2563eb)":"none",
                border:"1px solid transparent",
                color:activeView===v.id?"#ffffff":"#5a5a8a",padding:"5px 13px",borderRadius:6,cursor:"pointer",
                fontFamily:"inherit",fontSize:11,letterSpacing:0.5,transition:"all 0.2s",whiteSpace:"nowrap",
                boxShadow:activeView===v.id?"0 0 12px #7c3aed40":"none"}}>
                {v.label}
              </button>
            ))}
          </div>
          {results.length>0&&totalVulns>0&&(
            <div style={{background:"#ff174415",border:"1px solid #ff174440",color:"#DC2626",
              padding:"4px 12px",borderRadius:5,fontSize:11,fontFamily:"inherit",
              animation:"none",boxShadow:"0 0 10px #ff174420"}}>
              ⚠ {totalVulns} VULN{totalVulns>1?"S":""}
            </div>
          )}
          {results.length>0&&(
            <div style={{background:"#00e67610",border:"1px solid #00e67630",color:"#059669",
              padding:"4px 12px",borderRadius:5,fontSize:11,fontFamily:"inherit"}}>
              {results.length} SCANNED
            </div>
          )}
          {/* Backend status */}
          <div style={{display:"flex",alignItems:"center",gap:6,padding:"4px 10px",
            background:"#F7F8FC",border:"1px solid #DDE1EE",borderRadius:6}}>
            <div style={{width:7,height:7,borderRadius:"50%",
              background:backendOk?"#059669":"#D97706",
              boxShadow:`0 0 8px ${backendOk?"#059669":"#D97706"}`}}/>
            <span style={{color:backendOk?"#059669":"#D97706",fontSize:10,fontWeight:700,letterSpacing:1}}>
              {backendOk?"LIVE":"OFFLINE"}
            </span>
          </div>
          {/* User chip */}
          <div style={{display:"flex",alignItems:"center",gap:8,padding:"4px 12px",
            background:"#F7F8FC",border:"1px solid #DDE1EE",borderRadius:6}}>
            <div style={{width:22,height:22,borderRadius:"50%",
              background:`linear-gradient(135deg,${({"Admin":"#EF4444","Operator":"#D97706","Checker":"#8c9eff","Viewer":"#6666aa"})[user?.role]||"#666"},#1a1a2e)`,
              display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,fontWeight:700,color:"#fff"}}>
              {user?.username?.[0]?.toUpperCase()}
            </div>
            <div>
              <div style={{color:"#374151",fontSize:11,fontWeight:700,lineHeight:1.2}}>{user?.username}</div>
              <div style={{color:({"Admin":"#EF4444","Operator":"#D97706","Checker":"#8c9eff","Viewer":"#6666aa"})[user?.role]||"#888",fontSize:9,letterSpacing:1}}>{user?.role?.toUpperCase()}</div>
            </div>
            <button onClick={handleLogout} title="Sign out" style={{background:"none",border:"none",
              color:"#D1D5DB",cursor:"pointer",padding:"2px 4px",fontSize:14,lineHeight:1,
              borderRadius:3,transition:"color 0.2s"}}
              onMouseOver={e=>e.target.style.color="#EF4444"}
              onMouseOut={e=>e.target.style.color="#3a3a5a"}>
              ⏏
            </button>
          </div>
        </div>
      </div>

      {activeView==="api"&&(
        <APIScanPanel backendUrl={backendUrl} token={token}/>
      )}

      {activeView==="vpn"&&(
        <VPNScanPanel backendUrl={backendUrl} token={token}/>
      )}

      {activeView==="history"&&(
        <div style={{flex:1,minHeight:0,overflowY:"auto"}}>
          <HistoryPanel backendUrl={backendUrl} token={token} onLoadScan={(r)=>{
            setSelected(r);setResults([r]);setActiveView("scanner");
          }}/>
        </div>
      )}

      {/* User Management View (Admin only) */}
      {activeView==="users"&&user?.role==="Admin"&&(
        <div style={{flex:1,minHeight:0,overflowY:"auto"}}>
          <UserManagement backendUrl={backendUrl} token={token} currentUser={user}/>
        </div>
      )}

      {/* Scanner View */}
      {activeView==="scanner"&&(
        <div style={{display:"grid",gridTemplateColumns:"310px 1fr 460px",gridTemplateRows:"minmax(0,1fr)",flex:1,minHeight:0}}>
          {/* Left Panel */}
          <div style={{borderRight:"1px solid #DDE1EE",display:"flex",flexDirection:"column",background:"#FFFFFF",overflow:"hidden",minHeight:0}}>
            <div style={{padding:"14px 16px",borderBottom:"1px solid #DDE1EE",flexShrink:0}}>
              <div style={{color:"#9CA3AF",fontSize:10,letterSpacing:2,marginBottom:8}}>SCAN TARGETS</div>
              <textarea value={targets} onChange={e=>setTargets(e.target.value)}
                placeholder="Enter domains, one per line" style={{
                  width:"100%",height:110,background:"#F7F8FC",border:"1px solid #DDE1EE",
                  borderRadius:7,color:"#1A1D2E",fontFamily:"inherit",fontSize:12,
                  padding:"8px 10px",resize:"none",outline:"none",boxSizing:"border-box"}}/>
              <input value={backendUrl} onChange={e=>handleBackendUrlChange(e.target.value)}
                style={{width:"100%",background:"#F7F8FC",border:"1px solid #DDE1EE",borderRadius:5,
                  color:"#6B7280",fontFamily:"inherit",fontSize:11,padding:"5px 8px",
                  outline:"none",marginTop:6,boxSizing:"border-box"}}/>
              <button onClick={handleScan} disabled={scanning} style={{
                marginTop:8,width:"100%",padding:"10px",borderRadius:7,
                background:scanning?"#1a1a3a":"linear-gradient(135deg,#7c3aed,#2563eb)",
                border:"none",color:"#fff",fontFamily:"inherit",fontSize:13,fontWeight:700,
                cursor:scanning?"not-allowed":"pointer",letterSpacing:2,
                boxShadow:scanning?"none":"0 0 20px #7c3aed50",transition:"all 0.3s"}}>
                {scanning?`⏳ ${progress.current}/${progress.total} SCANNING...`:"⚡ LAUNCH DEEP SCAN"}
              </button>
              {scanning&&(
                <div style={{marginTop:8}}>
                  <div style={{background:"#F7F8FC",borderRadius:3,overflow:"hidden",height:3}}>
                    <div style={{height:"100%",background:"linear-gradient(90deg,#7c3aed,#2563eb)",
                      width:`${(progress.current/progress.total)*100}%`,transition:"width 0.5s"}}/>
                  </div>
                  <div style={{color:"#9CA3AF",fontSize:10,marginTop:4}}>→ {progress.current_target}</div>
                </div>
              )}
            </div>
            {/* Terminal */}
            <div style={{flex:1,overflowY:"auto",padding:"10px 14px",background:"#F0F2F8"}} ref={termRef}>
              {termLog.length===0&&!scanning&&(
                <div style={{color:"#E5E7EB",fontSize:11,lineHeight:1.8}}>
                  <div style={{color:"#D1D5DB",marginBottom:8}}>$ quantumshield --deep-scan --user={user?.username}</div>
                  <div>40+ parameters per target:</div>
                  {["TLS version & cipher analysis","Certificate deep inspection","Key exchange detection","Forward secrecy check","Vulnerability DB cross-ref","DNS security (CAA/DNSSEC)","HTTP security headers","CBOM generation","PQC readiness scoring"].map(l=>(
                    <div key={l}>· {l}</div>
                  ))}
                  <div style={{marginTop:8,color:"#D1D5DB"}}>Scans saved to database ✓</div>
                </div>
              )}
              {termLog.map((l,i)=>(
                <div key={i} style={{fontFamily:"inherit",fontSize:11,lineHeight:1.7,color:l.color,whiteSpace:"pre-wrap"}}>{l.msg}</div>
              ))}
            </div>
            {results.length>0&&(
              <div style={{padding:"10px 14px",borderTop:"1px solid #DDE1EE",flexShrink:0,display:"flex",flexDirection:"column",gap:6}}>
                <button onClick={exportCBOM} style={{width:"100%",padding:"8px",background:"#F7F8FC",
                  border:"1px solid #C8CDE0",color:"#6B7280",borderRadius:7,cursor:"pointer",
                  fontFamily:"inherit",fontSize:11,letterSpacing:1}}>
                  📥 EXPORT CBOM (JSON)
                </button>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6}}>
                  <button onClick={exportCSV} style={{padding:"7px",background:"#051a05",
                    border:"1px solid #1e844960",color:"#4ade80",borderRadius:7,cursor:"pointer",
                    fontFamily:"inherit",fontSize:10,letterSpacing:1}}>
                    📊 CSV
                  </button>
                  <button onClick={exportXML} style={{padding:"7px",background:"#050a1a",
                    border:"1px solid #1a527660",color:"#60a5fa",borderRadius:7,cursor:"pointer",
                    fontFamily:"inherit",fontSize:10,letterSpacing:1}}>
                    📋 XML
                  </button>
                </div>
                <button onClick={exportPDF} style={{width:"100%",padding:"8px",
                  background:"linear-gradient(135deg,#6A0DAD18,#1A5276 18)",
                  border:"1px solid #6A0DAD60",color:"#c084fc",borderRadius:7,cursor:"pointer",
                  fontFamily:"inherit",fontSize:11,letterSpacing:1,
                  boxShadow:"0 0 12px #6A0DAD30"}}>
                  📄 EXPORT PDF REPORT
                </button>
              </div>
            )}
          </div>

          {/* Middle Panel */}
          <div style={{borderRight:"1px solid #DDE1EE",overflowY:"auto",padding:"16px",minHeight:0,minWidth:0}}>
            {results.length>0?(
              <>
                <SummaryBar results={results}/>
                <div style={{color:"#4B5563",fontSize:10,fontWeight:700,letterSpacing:2,marginBottom:10}}>ASSET INVENTORY</div>
                <div style={{overflowX:"auto"}}>
                  <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
                    <thead><tr style={{borderBottom:"1px solid #DDE1EE"}}>
                      {["Asset","TLS","Cipher","Grade","FS","Cert","Expiry","Vulns","Score","Status"].map(h=>(
                        <th key={h} style={{padding:"7px 10px",textAlign:"left",color:"#9CA3AF",fontSize:10,letterSpacing:1,whiteSpace:"nowrap"}}>{h.toUpperCase()}</th>
                      ))}
                    </tr></thead>
                    <tbody>{results.map((r,i)=>{
                      const pqc=r.pqc_assessment||{};const tls=r.tls_info||{};
                      const cert=r.certificate||{};const vcount=r.vulnerabilities?.length||0;
                      return (
                        <tr key={i} onClick={()=>setSelected(r)} style={{borderBottom:"1px solid #EEF0F8",cursor:"pointer",background:selected?.target===r.target?"#EEF2FF":"transparent"}}>
                          <td style={{padding:"9px 10px",color:"#1B3FAB",fontFamily:"inherit",fontSize:11}}>{r.target}</td>
                          <td style={{padding:"9px 10px",color:tls.tls_version?.includes("1.3")?"#059669":"#D97706",whiteSpace:"nowrap"}}>{tls.tls_version||"—"}</td>
                          <td style={{padding:"9px 10px",color:"#6B7280",maxWidth:120,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{tls.cipher_suite||"—"}</td>
                          <td style={{padding:"9px 10px"}}>{tls.cipher_grade?<GradeBadge grade={tls.cipher_grade}/>:"—"}</td>
                          <td style={{padding:"9px 10px",color:tls.forward_secrecy?"#059669":"#EF4444"}}>{tls.forward_secrecy?"✓":"✗"}</td>
                          <td style={{padding:"9px 10px",color:cert.pqc_cert?"#059669":"#EF4444",whiteSpace:"nowrap"}}>{cert.key_type||"?"}-{cert.key_bits||0}</td>
                          <td style={{padding:"9px 10px",color:cert.days_until_expiry<30?"#EF4444":cert.days_until_expiry<90?"#D97706":"#6688aa",whiteSpace:"nowrap"}}>{cert.days_until_expiry!=null?`${cert.days_until_expiry}d`:"—"}</td>
                          <td style={{padding:"9px 10px",color:vcount>0?"#EF4444":"#3a5a3a"}}>{vcount>0?`⚠${vcount}`:"✓"}</td>
                          <td style={{padding:"9px 10px"}}><ScoreRing score={pqc.score||0} size={34}/></td>
                          <td style={{padding:"9px 10px"}}><Badge status={pqc.status} small/></td>
                        </tr>
                      );
                    })}</tbody>
                  </table>
                </div>
              </>
            ):( 
              <div style={{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",height:"100%",minHeight:420}}>
                <div style={{position:"relative",marginBottom:24}}>
                  <div style={{fontSize:80,lineHeight:1,filter:"drop-shadow(0 0 30px #7c3aed40)"}}>⚛</div>
                  <div style={{position:"absolute",inset:0,background:"radial-gradient(circle,#7c3aed15 0%,transparent 70%)",borderRadius:"50%"}}/>
                </div>
                <div style={{fontSize:18,color:"#3a3a7a",letterSpacing:4,fontWeight:800,marginBottom:8}}>QUANTUMSHIELD</div>
                <div style={{fontSize:11,color:"#E5E7EB",letterSpacing:2,marginBottom:4}}>40+ PARAMETERS · NIST FIPS 203/204/205</div>
                <div style={{fontSize:10,color:"#E5E7EB",marginBottom:28}}>Logged in as <span style={{color:"#6644aa"}}>{user?.username}</span> · {user?.role}</div>
                <div style={{display:"flex",gap:8,flexWrap:"wrap",justifyContent:"center",maxWidth:400}}>
                  {["pnbindia.in","google.com","cloudflare.com","sbi.co.in"].map(t=>(
                    <button key={t} onClick={()=>{setTargets(t);}} style={{
                      background:"#F7F8FC",border:"1px solid #DDE1EE",color:"#9CA3AF",
                      padding:"5px 12px",borderRadius:5,cursor:"pointer",fontFamily:"inherit",
                      fontSize:11,transition:"all 0.2s"}}
                      onMouseOver={e=>{e.target.style.borderColor="#7c3aed";e.target.style.color="#7c3aed";}}
                      onMouseOut={e=>{e.target.style.borderColor="#DDE1EE";e.target.style.color="#9CA3AF";}}>
                      {t}
                    </button>
                  ))}
                </div>
                <div style={{fontSize:10,color:"#E5E7EB",marginTop:12}}>↑ click a target to load it, or type your own</div>
              </div>
            )}
          </div>

          {/* Right Panel */}
          <div style={{overflowY:"auto",minHeight:0,background:"#FFFFFF"}}><DetailPanel result={selected} backendUrl={backendUrl} token={token}/></div>
        </div>
      )}

      {/* Algorithms View */}
      {activeView==="algorithms"&&(
        <div style={{flex:1,minHeight:0,overflowY:"auto",padding:"24px 32px"}}>
          <div style={{maxWidth:960,margin:"0 auto",width:"100%",boxSizing:"border-box"}}>
          <div style={{color:"#9CA3AF",fontSize:10,letterSpacing:2,marginBottom:20}}>NIST POST-QUANTUM CRYPTOGRAPHY STANDARDS — FINAL (2024)</div>
          <div style={{display:"grid",gap:14,marginBottom:28}}>
            {[
              {std:"FIPS 203",name:"ML-KEM",full:"Module Lattice-based Key Encapsulation Mechanism",variants:["ML-KEM-512 (Level 1)","ML-KEM-768 (Level 3) ★ Recommended","ML-KEM-1024 (Level 5)"],replaces:"RSA/ECDH Key Exchange",basis:"Module Learning With Errors (MLWE)",color:"#60a5fa",icon:"🔑"},
              {std:"FIPS 204",name:"ML-DSA",full:"Module Lattice-based Digital Signature Algorithm",variants:["ML-DSA-44 (Level 2)","ML-DSA-65 (Level 3) ★ Recommended","ML-DSA-87 (Level 5)"],replaces:"RSA/ECDSA Digital Signatures",basis:"Module Learning With Errors (MLWE)",color:"#34d399",icon:"✍️"},
              {std:"FIPS 205",name:"SLH-DSA",full:"Stateless Hash-based Digital Signature Algorithm",variants:["SLH-DSA-SHA2-128s/f (Level 1)","SLH-DSA-SHA2-192s/f (Level 3) ★","SLH-DSA-SHA2-256s/f (Level 5)"],replaces:"RSA/ECDSA (conservative, hash-based)",basis:"Hash functions (SPHINCS+)",color:"#1B3FAB",icon:"🌳"},
            ].map(algo=>(
              <div key={algo.std} style={{background:"#F7F8FC",border:`1px solid ${algo.color}30`,borderLeft:`4px solid ${algo.color}`,borderRadius:10,padding:"18px 20px"}}>
                <div style={{display:"flex",gap:12,alignItems:"center",marginBottom:10}}>
                  <span style={{background:`${algo.color}22`,color:algo.color,padding:"2px 10px",borderRadius:4,fontSize:11,fontWeight:700,letterSpacing:1,fontFamily:"inherit"}}>{algo.std}</span>
                  <span style={{color:"#1A1D2E",fontWeight:800,fontSize:18}}>{algo.name}</span>
                  <span style={{fontSize:20}}>{algo.icon}</span>
                </div>
                <div style={{color:"#6B7280",fontSize:12,marginBottom:6}}>{algo.full}</div>
                <div style={{color:"#9CA3AF",fontSize:11,marginBottom:4}}>MATHEMATICAL BASIS: <span style={{color:"#374151"}}>{algo.basis}</span></div>
                <div style={{color:"#9CA3AF",fontSize:11,marginBottom:10}}>REPLACES: <span style={{color:"#D97706"}}>{algo.replaces}</span></div>
                <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                  {algo.variants.map(v=>(
                    <span key={v} style={{background:v.includes("★")?`${algo.color}22`:"#1a1a2e",border:`1px solid ${v.includes("★")?algo.color:"#E5E7EB"}`,color:v.includes("★")?algo.color:"#6B7280",padding:"3px 10px",borderRadius:4,fontSize:11,fontFamily:"inherit"}}>{v}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div style={{background:"#0e0000",border:"1px solid #ff174430",borderRadius:10,padding:"18px 20px"}}>
            <div style={{color:"#DC2626",fontWeight:700,fontSize:13,marginBottom:12}}>⚠ QUANTUM-VULNERABLE ALGORITHMS — HARVEST NOW, DECRYPT LATER RISK</div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10}}>
              {[["RSA","CRITICAL","Shor's algorithm — any key size","Signatures, Key Exchange"],
                ["ECDSA/ECDH","CRITICAL","Shor's algorithm breaks ECC","Signatures, TLS Key Exchange"],
                ["DH/DSA","CRITICAL","Shor's algorithm breaks DLP","Legacy Key Exchange"],
                ["AES-128","HIGH","Grover's: 64-bit effective security","Symmetric Encryption"],
                ["SHA-1","CRITICAL","Classical collision attacks","Certificate Signing"],
                ["3DES","CRITICAL","SWEET32 + Grover's ~40-bit","Legacy Block Cipher"],
                ["RC4","CRITICAL","Statistical biases (RFC 7465)","Stream Cipher"],
                ["MD5","CRITICAL","Collision attacks since 2004","Hash / Cert Signing"],
                ["RSA<2048","CRITICAL","Classically breakable today","Legacy Certificates"],
              ].map(([algo,risk,reason,use])=>(
                <div key={algo} style={{background:"#FEF2F2",border:"1px solid #ff174415",borderRadius:7,padding:"10px 12px"}}>
                  <div style={{color:"#DC2626",fontWeight:700,fontSize:13,fontFamily:"inherit"}}>{algo}</div>
                  <div style={{color:"#B91C1C",fontSize:10,fontWeight:700,letterSpacing:1,marginTop:3}}>{risk}</div>
                  <div style={{color:"#886666",fontSize:11,marginTop:3}}>{reason}</div>
                  <div style={{color:"#664444",fontSize:10,marginTop:2}}>{use}</div>
                </div>
              ))}
            </div>
          </div>
          </div>
        </div>
      )}

      {/* About View */}
      {activeView==="about"&&(
        <div style={{flex:1,minHeight:0,overflowY:"auto",padding:"32px",background:"#F7F8FC"}}>
          <div style={{maxWidth:900,margin:"0 auto"}}>
            {/* Hero */}
            <div style={{textAlign:"center",marginBottom:48,padding:"48px 32px",
              background:"linear-gradient(135deg,#F5F3FF,#EEF2FF)",
              border:"1px solid #DDE1EE",borderRadius:16,
              boxShadow:"0 0 60px #7c3aed15"}}>
              <div style={{fontSize:64,marginBottom:16,filter:"drop-shadow(0 0 20px #7c3aed20)"}}>⚛</div>
              <div style={{color:"#1A1D2E",fontWeight:900,fontSize:28,letterSpacing:4,marginBottom:6}}>QUANTUMSHIELD</div>
              <div style={{color:"#7C3AED",fontWeight:700,fontSize:14,letterSpacing:3,marginBottom:4}}>POST-QUANTUM CRYPTOGRAPHY SCANNER</div>
              <div style={{color:"#4B5563",fontSize:12,marginBottom:16}}>NIST FIPS 203/204/205 · Active ML-KEM key-exchange detection</div>
              <div style={{display:"flex",justifyContent:"center",gap:8,flexWrap:"wrap"}}>
                {[["FIPS 203","ML-KEM","#60a5fa"],["FIPS 204","ML-DSA","#34d399"],["FIPS 205","SLH-DSA","#a78bfa"],
                  ["Active","KEX Probe","#D97706"],["CycloneDX","v1.4 CBOM","#f472b6"]].map(([s,n,c])=>(
                  <div key={s} style={{background:`${c}18`,border:`1px solid ${c}44`,borderRadius:6,padding:"6px 14px",textAlign:"center"}}>
                    <div style={{color:c,fontWeight:700,fontSize:10,letterSpacing:1}}>{s}</div>
                    <div style={{color:`${c}cc`,fontSize:10,marginTop:1}}>{n}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Real-world finding callout */}
            <div style={{background:"#FEF2F2",border:"1px solid #ff174430",borderLeft:"4px solid #ff1744",
              borderRadius:10,padding:"16px 20px",marginBottom:32}}>
              <div style={{color:"#DC2626",fontWeight:800,fontSize:14,marginBottom:6}}>
                🚨 Why this matters
              </div>
              <div style={{color:"#7F1D1D",fontSize:12,lineHeight:1.7}}>
                Most of the public internet still relies on RSA and ECDSA, which Shor's algorithm
                breaks on a sufficiently large quantum computer. Even sites that have deployed
                hybrid ML-KEM key exchange usually still present classical certificates — so
                <strong style={{color:"#EF4444"}}> almost nothing is fully quantum-safe yet.</strong>{" "}
                QuantumShield measures exactly where each endpoint stands and what to fix first.
              </div>
            </div>

            {/* Feature grid */}
            <div style={{color:"#9CA3AF",fontSize:10,letterSpacing:2,marginBottom:16}}>CAPABILITIES</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:32}}>
              {[
                {icon:"🔬",title:"Deep TLS Inspection",desc:"Real TLS handshake, cipher grading A–F, TLS version probing via 3 strategies, key exchange detection.",color:"#60a5fa"},
                {icon:"📜",title:"X.509 Certificate Audit",desc:"25+ certificate fields: key type/bits, expiry, CT logs, OCSP, SANs, key usage, self-signed detection.",color:"#34d399"},
                {icon:"⚛",title:"PQC Score Engine (0–100)",desc:"40+ parameters, NIST-aligned scoring. Quantum Safe / PQC Ready / Transitioning / Vulnerable badges.",color:"#1B3FAB"},
                {icon:"🛡️",title:"12-CVE Vulnerability DB",desc:"POODLE, BEAST, SWEET32, RC4, FREAK, LOGJAM, DROWN, NULL_CIPHER, MD5_HASH, HNDL and more.",color:"#f472b6"},
                {icon:"🌐",title:"DNS Security Analysis",desc:"CAA records, DNSSEC, IPv4/IPv6, SPF, DMARC. Flags missing controls that enable cert mis-issuance.",color:"#D97706"},
                {icon:"🔒",title:"HTTP Security Headers",desc:"HSTS, CSP, X-Frame-Options, Referrer-Policy, COOP, COEP — with specific fix recommendations.",color:"#fb923c"},
                {icon:"📊",title:"CBOM (CycloneDX v1.4)",desc:"CycloneDX-compliant Cryptographic Bill of Materials. JSON + PDF export for GRC tool integration.",color:"#22d3ee"},
                {icon:"🤖",title:"AI Explanations (Gemini)",desc:"Plain-English analysis for CEO brief, board report, or technical team. One click per scan.",color:"#c084fc"},
                {icon:"⚡",title:"Quantum Attack Simulator",desc:"Animates Shor's Algorithm attack on any scanned target. Shows break time classical vs quantum.",color:"#DC2626"},
                {icon:"🔐",title:"Auth + RBAC + Audit Trail",desc:"JWT auth, bcrypt passwords, SQLite DB. Admin/Operator/Checker/Viewer roles. Full audit log.",color:"#4ade80"},
              ].map(({icon,title,desc,color})=>(
                <div key={title} style={{background:"#FFFFFF",border:`1px solid ${color}20`,
                  borderLeft:`3px solid ${color}`,borderRadius:9,padding:"14px 16px",
                  display:"flex",gap:12,transition:"border-color 0.2s"}}>
                  <div style={{fontSize:22,flexShrink:0}}>{icon}</div>
                  <div>
                    <div style={{color:"#1A1D2E",fontWeight:700,fontSize:12,marginBottom:4}}>{title}</div>
                    <div style={{color:"#4B5563",fontSize:11,lineHeight:1.6}}>{desc}</div>
                  </div>
                </div>
              ))}
            </div>

            {/* Tech stack */}
            <div style={{color:"#9CA3AF",fontSize:10,letterSpacing:2,marginBottom:16}}>TECH STACK</div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:32}}>
              {[
                ["Python 3.11","Backend","#3b82f6"],["FastAPI","API Framework","#009688"],
                ["SQLAlchemy","ORM + SQLite","#ff9800"],["JWT + bcrypt","Auth Security","#e91e63"],
                ["React 18","Frontend","#61dafb"],["Vite","Build Tool","#646cff"],
                ["reportlab","PDF Engine","#ff5722"],["Google Gemini","AI Layer","#10a37f"],
              ].map(([tech,role,color])=>(
                <div key={tech} style={{background:"#F7F8FC",border:`1px solid ${color}30`,borderRadius:7,padding:"10px 12px",textAlign:"center"}}>
                  <div style={{color,fontWeight:700,fontSize:11,fontFamily:"inherit"}}>{tech}</div>
                  <div style={{color:"#9CA3AF",fontSize:10,marginTop:3}}>{role}</div>
                </div>
              ))}
            </div>

            {/* Deploy info */}
            <div style={{background:"#F7F8FC",border:"1px solid #DDE1EE",borderRadius:10,padding:"16px 20px",textAlign:"center"}}>
              <div style={{color:"#9CA3AF",fontSize:10,letterSpacing:2,marginBottom:10}}>DEPLOYMENT</div>
              <div style={{display:"flex",justifyContent:"center",gap:20,flexWrap:"wrap",marginBottom:10}}>
                {[["Frontend","Vercel","#000000","Always-on CDN"],["Backend","Render","#46E3B7","Free tier + UptimeRobot"],
                  ["Database","SQLite","#003B57","Auto-created on startup"],["CI/CD","GitHub","#f0f0f0","Auto-deploy on push"]].map(([layer,service,c,note])=>(
                  <div key={layer} style={{textAlign:"center"}}>
                    <div style={{color:"#6B7280",fontSize:9,letterSpacing:1}}>{layer.toUpperCase()}</div>
                    <div style={{color:"#1A1D2E",fontWeight:700,fontSize:13,fontFamily:"inherit"}}>{service}</div>
                    <div style={{color:"#9CA3AF",fontSize:10}}>{note}</div>
                  </div>
                ))}
              </div>
              <div style={{color:"#D1D5DB",fontSize:10}}>QuantumShield · Post-Quantum Cryptography Scanner</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
