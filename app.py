from pathlib import Path
from datetime import datetime,timedelta
import csv,json,re,hashlib
import streamlit as st
import joblib,hmac,os
from sqlalchemy import create_engine,Column,Integer,String,Text,Boolean,DateTime
from sqlalchemy.orm import declarative_base,sessionmaker

R=Path(__file__).resolve().parent
engine=create_engine(f"sqlite:///{R/'sti_app.db'}",connect_args={"check_same_thread":False})
Session=sessionmaker(bind=engine); Base=declarative_base()
class User(Base):
 __tablename__="users"; id=Column(Integer,primary_key=True); username=Column(String,unique=True,nullable=False); password_hash=Column(String,nullable=False); role=Column(String,default="admin"); active=Column(Boolean,default=True); created_at=Column(DateTime,default=datetime.utcnow)
class Content(Base):
 __tablename__="content"; id=Column(Integer,primary_key=True); topic=Column(String); language=Column(String); title=Column(String); body=Column(Text); source=Column(String); version=Column(String); status=Column(String,default="pending_review"); reviewer=Column(String); reviewed_at=Column(DateTime); created_at=Column(DateTime,default=datetime.utcnow); updated_at=Column(DateTime,default=datetime.utcnow)
class Inquiry(Base):
 __tablename__="inquiries"; id=Column(Integer,primary_key=True); session_hash=Column(String); language=Column(String); intent=Column(String); entities_json=Column(Text); raw_text=Column(Text); consent_to_store=Column(Boolean); created_at=Column(DateTime,default=datetime.utcnow)
class Audit(Base):
 __tablename__="audit_logs"; id=Column(Integer,primary_key=True); actor=Column(String); action=Column(String); object_type=Column(String); object_id=Column(String); details=Column(Text); created_at=Column(DateTime,default=datetime.utcnow)
class DemographicProfile(Base):
 __tablename__="demographic_profiles"; id=Column(Integer,primary_key=True); session_hash=Column(String,index=True); gender=Column(String); age_bracket=Column(String); sexually_active=Column(String); residence=Column(String); nearest_health_facility=Column(String); consent_to_store=Column(Boolean,default=False); created_at=Column(DateTime,default=datetime.utcnow)
def hash_password(password,salt=None):
 salt=salt or os.urandom(16)
 key=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,200000)
 return f"pbkdf2_sha256$200000${salt.hex()}${key.hex()}"
def verify_password(password,stored):
 try:
  alg,it,salt_hex,key_hex=stored.split("$")
  key=hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt_hex),int(it))
  return hmac.compare_digest(key.hex(),key_hex)
 except Exception:return False
def secret_value(name,default=None):
 try:return st.secrets[name]
 except Exception:return os.environ.get(name,default)
def boot():
 Base.metadata.create_all(engine); s=Session()
 admin_user=secret_value("ADMIN_USERNAME"); admin_password=secret_value("ADMIN_PASSWORD")
 # Deployment Secrets are authoritative: synchronize the admin on each restart.
 if admin_user and admin_password:
  configured=s.query(User).filter_by(role="admin").order_by(User.id).first()
  if configured:
   configured.username=admin_user
   configured.password_hash=hash_password(admin_password)
   configured.active=True
  else:
   s.add(User(username=admin_user,password_hash=hash_password(admin_password),role="admin",active=True))
 if s.query(Content).count()==0:
  with open(R/"data/content_seed.csv",encoding="utf8") as f:
   for x in csv.DictReader(f): s.add(Content(topic=x["topic"],language=x["language"],title=x["title"],body=x["body"],source=x["source"],version=x["version"],status="pending_review"))
 s.commit(); s.close()
@st.cache_resource
def model():
 try:return joblib.load(R/"models/intent_model.joblib")
 except:return None
def redact(t):
 t=re.sub(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}',"[email redacted]",t)
 return re.sub(r'(?<!\w)(?:\+?\d[\d\s\-()]{7,}\d)(?!\w)',"[phone/number redacted]",t)
def extract(t):
 x=t.lower(); o={"topics":[],"symptoms":[],"durations":[],"exposures":[]}
 maps=[("topics",{"gonorrhoea":["gonorrhoea","gonorrhea","kisonono"],"chlamydia":["chlamydia"],"syphilis":["syphilis","kaswende"],"hiv":["hiv","ukimwi"],"herpes":["herpes"],"hpv":["hpv"],"trichomoniasis":["trichomoniasis"]}),("symptoms",{"dysuria":["burning when urinating","painful urination","kuungua nikikojoa","maumivu nikikojoa"],"genital_discharge":["yellow discharge","genital discharge","abnormal discharge","uchafu sehemu za siri","uchafu usio wa kawaida"],"pelvic_pain":["pelvic pain","maumivu ya nyonga"],"testicular_pain":["testicular pain","maumivu ya korodani"],"genital_sores":["genital sores","vidonda sehemu za siri"],"itching":["itching","kuwashwa"],"rash":["rash","upele"],"fever":["fever","homa"]}),("exposures",{"unprotected_sex":["unprotected sex","sex without condom","ngono bila kondomu"],"oral_sex":["oral sex","ngono ya mdomo"],"new_partner":["new partner","mwenza mpya"]})]
 for typ,mp in maps:
  for k,v in mp.items():
   if any(a in x for a in v):o[typ].append(k)
 o["durations"]=re.findall(r'\b\d+\s*(?:days?|weeks?|months?|siku|wiki|mwezi|miezi)\b',x); return o
def log(s,a,act,typ,oid="",d=""):s.add(Audit(actor=a,action=act,object_type=typ,object_id=str(oid),details=d))
boot(); st.set_page_config(page_title="STI Information Assistant",page_icon="🩺",layout="wide")
st.title("STI Information Assistant"); st.caption("Educational/research prototype — not a diagnostic or prescribing system.")
mode=st.sidebar.radio("Open",["Learner assistant","Admin"])
if mode=="Learner assistant":
 lang=st.selectbox("Language / Lugha",[("English","en"),("Kiswahili","sw")],format_func=lambda z:z[0])[1]
 st.info("Do not enter identifying information. Symptoms alone cannot confirm an STI." if lang=="en" else "Usiweke taarifa zinazokutambulisha. Dalili pekee haziwezi kuthibitisha STI.")
 st.subheader("Basic information" if lang=="en" else "Taarifa za msingi")
 st.caption("These fields are used only for aggregate research reporting. Avoid entering a home address." if lang=="en" else "Taarifa hizi hutumika tu kwa ripoti za jumla za utafiti. Usiweke anwani ya nyumbani.")
 c1,c2=st.columns(2)
 with c1:
  gender=st.selectbox("Gender" if lang=="en" else "Jinsia",["Prefer not to say","Male","Female","Other"])
  age_bracket=st.selectbox("Age bracket" if lang=="en" else "Kundi la umri",["Prefer not to say","18-19 years","20-22 years","23-25 years"])
  sexually_active=st.selectbox("Sexually active?" if lang=="en" else "Je, unashiriki ngono?",["Prefer not to say","Yes","No"])
 with c2:
  residence=st.text_input("Residence (county/town only)" if lang=="en" else "Makazi (kaunti/mji pekee)",placeholder="e.g. Nairobi")
  nearest_health_facility=st.text_input("Nearest health facility" if lang=="en" else "Kituo cha afya kilicho karibu",placeholder="e.g. local clinic or hospital")
 demographic_consent=st.checkbox("I consent to storing these basic details in de-identified form for aggregate research reporting." if lang=="en" else "Ninakubali taarifa hizi za msingi zihifadhiwe bila utambulisho kwa ripoti za jumla za utafiti.")
 q=st.text_area("Ask an STI education question" if lang=="en" else "Uliza swali la elimu kuhusu STI",height=120)
 consent=st.checkbox("I consent to storing a redacted copy for prototype evaluation." if lang=="en" else "Ninakubali nakala iliyofichwa taarifa binafsi ihifadhiwe kwa tathmini ya mfano huu.")
 if st.button("Process question" if lang=="en" else "Chambua swali",type="primary") and q.strip():
  m=model(); intent=m.predict([q])[0] if m else "general_information"; e=extract(q); st.subheader("NLP extraction"); st.json({"intent":intent,"entities":e})
  s=Session(); topic=e["topics"][0] if e["topics"] else "general"; items=s.query(Content).filter_by(topic=topic,language=lang,status="approved").all()
  if not items and topic!="general":items=s.query(Content).filter_by(topic="general",language=lang,status="approved").all()
  st.subheader("Educational content" if lang=="en" else "Maudhui ya elimu")
  if not items:st.warning("No reviewer-approved content is available for this topic yet." if lang=="en" else "Bado hakuna maudhui yaliyoidhinishwa na mkaguzi kwa mada hii.")
  for c in items:st.markdown(f"### {c.title}\n{c.body}"); st.caption(f"Source: {c.source} | Version: {c.version} | Reviewer: {c.reviewer}")
  if e["symptoms"]:st.warning("Symptoms do not confirm gonorrhoea or another STI. Consider professional assessment and appropriate testing." if lang=="en" else "Dalili hazithibitishi kisonono au STI nyingine. Fikiria kupata tathmini ya mhudumu wa afya na kipimo kinachofaa.")
  session_id=hashlib.sha256((st.session_state.get("_profile_session","browser-session")).encode()).hexdigest()[:20]
  if consent:s.add(Inquiry(session_hash=session_id,language=lang,intent=intent,entities_json=json.dumps(e),raw_text=redact(q),consent_to_store=True))
  if demographic_consent:
   s.add(DemographicProfile(session_hash=session_id,gender=gender,age_bracket=age_bracket,sexually_active=sexually_active,residence=redact(residence.strip())[:100],nearest_health_facility=redact(nearest_health_facility.strip())[:150],consent_to_store=True))
  s.commit();s.close()
else:
 if not st.session_state.get("admin_ok"):
  configured_user=secret_value("ADMIN_USERNAME"); configured_password=secret_value("ADMIN_PASSWORD")
  if not configured_user or not configured_password:
   st.error("Admin login is not configured. Add ADMIN_USERNAME and ADMIN_PASSWORD in Streamlit App Settings > Secrets, save, then reboot the app.")
   st.stop()
  st.info("Use the ADMIN_USERNAME and ADMIN_PASSWORD currently configured in Streamlit Secrets.")
  u=st.text_input("Username"); p=st.text_input("Password",type="password")
  if st.button("Log in"):
   s=Session(); z=s.query(User).filter_by(username=u,active=True).first(); ok=z and verify_password(p,z.password_hash);s.close()
   if ok:st.session_state.admin_ok=True;st.session_state.admin_user=u;st.rerun()
   else:st.error("Invalid credentials.")
 else:
  actor=st.session_state.get("admin_user","admin"); st.success(f"Signed in as {actor}")
  if st.button("Log out"):st.session_state.admin_ok=False;st.rerun()
  t1,t2,t3,t4,t5,t6,t7=st.tabs(["Review content","Create content","Approved content","Aggregate reporting","Audit log","Privacy / retention","Account"])
  with t1:
   s=Session(); pending=s.query(Content).filter_by(status="pending_review").order_by(Content.id).all()
   st.caption("Approval must be performed by an actual qualified reviewer. The application does not manufacture expert approval.")
   for c in pending:
    with st.expander(f"#{c.id} [{c.language}] {c.title}"):
     st.write(c.body);st.caption(f"{c.source} | v{c.version}");rv=st.text_input("Reviewer name / role",key=f"r{c.id}");a,b=st.columns(2)
     if a.button("Approve",key=f"a{c.id}"):
      if not rv.strip():st.error("Enter the real reviewer name/role.")
      else:c.status="approved";c.reviewer=rv.strip();c.reviewed_at=datetime.utcnow();c.updated_at=datetime.utcnow();log(s,actor,"approve","content",c.id,f"reviewer={rv.strip()}");s.commit();st.rerun()
     if b.button("Archive",key=f"x{c.id}"):c.status="archived";c.updated_at=datetime.utcnow();log(s,actor,"archive","content",c.id);s.commit();st.rerun()
   s.close()
  with t2:
   with st.form("new"):
    tp=st.text_input("Topic",value="general");la=st.selectbox("Language",["en","sw"]);ti=st.text_input("Title");bo=st.text_area("Body");so=st.text_input("Source");ve=st.text_input("Version",value="1.0")
    if st.form_submit_button("Save as pending review"):
     s=Session();c=Content(topic=tp,language=la,title=ti,body=bo,source=so,version=ve,status="pending_review");s.add(c);s.flush();log(s,actor,"create","content",c.id,"pending_review");s.commit();s.close();st.success("Saved as pending_review.")
  with t3:
   s=Session()
   for c in s.query(Content).filter_by(status="approved").all():st.markdown(f"**#{c.id} [{c.language}] {c.title}**");st.write(c.body);st.caption(f"Reviewer: {c.reviewer} | Source: {c.source}")
   s.close()
  with t4:
   st.subheader("Aggregate participant reporting")
   st.caption("Only grouped counts are shown. Individual demographic records and inquiry text are not displayed together.")
   s=Session(); rows=s.query(DemographicProfile).filter_by(consent_to_store=True).all()
   st.metric("Consenting demographic records",len(rows))
   def counts(field):
    out={}
    for r in rows:
     v=getattr(r,field) or "Not provided";out[v]=out.get(v,0)+1
    return [{"category":k,"count":v} for k,v in sorted(out.items(),key=lambda x:(-x[1],x[0]))]
   a,b=st.columns(2)
   with a:
    st.markdown("**Gender**");st.dataframe(counts("gender"),use_container_width=True,hide_index=True)
    st.markdown("**Sexual activity**");st.dataframe(counts("sexually_active"),use_container_width=True,hide_index=True)
    st.markdown("**Residence**");st.dataframe(counts("residence"),use_container_width=True,hide_index=True)
   with b:
    st.markdown("**Age bracket**");st.dataframe(counts("age_bracket"),use_container_width=True,hide_index=True)
    st.markdown("**Nearest health facility**");st.dataframe(counts("nearest_health_facility"),use_container_width=True,hide_index=True)
   s.close()
  with t5:
   s=Session();st.dataframe([{"time":x.created_at,"actor":x.actor,"action":x.action,"object":f"{x.object_type}:{x.object_id}","details":x.details} for x in s.query(Audit).order_by(Audit.id.desc()).limit(200)],use_container_width=True);s.close()
  with t6:
   days=st.number_input("Delete stored inquiries older than N days",1,3650,90)
   if st.button("Run retention cleanup"):
    s=Session();cutoff=datetime.utcnow()-timedelta(days=int(days));n=s.query(Inquiry).filter(Inquiry.created_at<cutoff).delete();d=s.query(DemographicProfile).filter(DemographicProfile.created_at<cutoff).delete();log(s,actor,"retention_cleanup","research_data","",f"inquiries={n}; demographics={d}");s.commit();s.close();st.success(f"Deleted {n} inquiries and {d} demographic records.")
  with t7:
   old=st.text_input("Current password",type="password");new=st.text_input("New password",type="password")
   if st.button("Change password"):
    s=Session();u=s.query(User).filter_by(username=actor).first()
    if not u or not verify_password(old,u.password_hash):st.error("Current password is incorrect.")
    elif len(new)<12:st.error("Use at least 12 characters.")
    else:u.password_hash=hash_password(new);log(s,actor,"password_change","user",u.id);s.commit();st.success("Password changed.")
    s.close()
