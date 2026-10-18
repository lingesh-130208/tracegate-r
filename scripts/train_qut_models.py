#!/usr/bin/env python3
"""Train TraceGate-R's 48-feature classifiers from the public QUT-DV25 archive."""
import argparse, hashlib, json, os, re, subprocess, sys, tempfile, urllib.request, zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
import joblib, numpy as np, pandas as pd, sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
ROOT=Path(__file__).resolve().parents[1]
SCHEMA=ROOT/'data/model_feature_names.json'; URL='https://dataverse.harvard.edu/api/access/datafile/11542393'
DOI='https://doi.org/10.7910/DVN/LBMXJY'; LICENSE='CC0 1.0 Universal'; MD5='09553107f6263a17a2db513f6bfabb44'
PREFIX='QUT-DV25_Datasets/QUT-DV25_Processed_Datasets/'; SEED=42
FILES=('logistic_regression.joblib','random_forest.joblib','feature_names.json','metrics.json','training_manifest.json')
def digest(path, alg='sha256'):
 d=hashlib.md5(usedforsecurity=False) if alg=='md5' else hashlib.sha256()
 with Path(path).open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''): d.update(b)
 return d.hexdigest()
DATASET_SIZE = 2_142_243_738

def fetch(path):
 path=Path(path).expanduser().resolve()
 if path.exists():
  if path.stat().st_size != DATASET_SIZE or digest(path,'md5')!=MD5: raise ValueError('Dataset checksum/size mismatch; refusing to train')
  return path
 path.parent.mkdir(parents=True,exist_ok=True); part=path.with_name(path.name+'.download.part')
 if part.exists(): raise FileExistsError(f'Inspect partial download before retry: {part}')
 md=hashlib.md5(usedforsecurity=False)
 request=urllib.request.Request(URL,headers={
  'User-Agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36',
  'Accept':'application/octet-stream,*/*;q=0.8',
  'Range':f'bytes=0-{DATASET_SIZE-1}',
  'Referer':'https://dataverse.harvard.edu/',
 })
 try:
  with urllib.request.urlopen(request,timeout=120) as response, part.open('xb') as w:
   status=getattr(response,'status',200); content_range=response.headers.get('Content-Range')
   if status not in (200,206): raise IOError(f'Dataverse returned HTTP {status}')
   if status==206 and content_range != f'bytes 0-{DATASET_SIZE-1}/{DATASET_SIZE}':
    raise IOError(f'Unexpected dataset Content-Range: {content_range!r}')
   length=response.headers.get('Content-Length')
   if length and int(length)!=DATASET_SIZE: raise IOError(f'Unexpected dataset Content-Length: {length}')
   while True:
    b=response.read(4*1024*1024)
    if not b: break
    w.write(b); md.update(b)
    if part.stat().st_size % (256*1024*1024) < len(b): print(f'Downloaded {part.stat().st_size/(1024**3):.2f} GiB',file=sys.stderr)
  if part.stat().st_size!=DATASET_SIZE: raise IOError(f'Dataset size mismatch: received {part.stat().st_size}, expected {DATASET_SIZE}')
  if md.hexdigest().lower()!=MD5: raise ValueError(f'Downloaded dataset MD5 mismatch: {md.hexdigest()}')
  os.replace(part,path); return path
 except Exception as exc:
  part.unlink(missing_ok=True)
  if isinstance(exc,urllib.error.HTTPError):
   body=exc.read(500).decode('utf-8',errors='replace')
   raise RuntimeError(f'Dataverse HTTP {exc.code}: {body[:300]}') from exc
  raise
def names_from(path):
 x=json.loads(Path(path).read_text(encoding='utf-8'))
 if not isinstance(x,list) or len(x)!=48 or len(set(x))!=48 or any(not isinstance(v,str) or not v.strip() for v in x): raise ValueError('Schema must have 48 unique ordered names')
 return x
def norm(v): return str(v).strip().replace(' ','_')
def tag(path): return PurePosixPath(path).parent.name.replace('QUT-DV25_','').replace('_Traces','')
def read_frames(archive,names):
 needed={}
 for n in names:
  t,sep,c=n.partition('__')
  if not sep or not c: raise ValueError(f'Malformed feature: {n}')
  needed.setdefault(t,set()).add(c)
 out={}
 with zipfile.ZipFile(archive) as z:
  files=sorted(n for n in z.namelist() if n.startswith(PREFIX) and n.lower().endswith('.csv'))
  if len(files)!=6: raise ValueError(f'Expected six processed CSVs; found {len(files)}')
  for fn in files:
   t=tag(fn)
   if t in out: raise ValueError(f'Duplicate trace category: {t}')
   with z.open(fn) as f: header=list(pd.read_csv(f,nrows=0).columns)
   cols={}
   for raw in header: cols.setdefault(norm(raw),[]).append(str(raw))
   for k in ('Package_Name','Level'):
    if len(cols.get(k,[]))!=1: raise ValueError(f'{fn} needs one {k} column')
   use=[cols['Package_Name'][0],cols['Level'][0]]
   for c in needed.get(t,set()):
    m=cols.get(c,[])
    if len(m)!=1: raise ValueError(f'Expected one source column for {t}__{c}; found {len(m)}')
    use.append(m[0])
   with z.open(fn) as f: df=pd.read_csv(f,usecols=list(dict.fromkeys(use)),low_memory=False)
   df.columns=[norm(c) for c in df.columns]
   if df.columns.duplicated().any(): raise ValueError(f'Ambiguous columns in {fn}')
   df['Package_Name']=df['Package_Name'].astype(str).str.strip()
   if df['Package_Name'].eq('').any() or df['Package_Name'].duplicated().any(): raise ValueError(f'Empty/duplicate package IDs in {fn}')
   y=pd.to_numeric(df['Level'],errors='raise')
   if y.isna().any() or not set(y.unique())<={0,1}: raise ValueError(f'Invalid labels in {fn}')
   df['Level']=y.astype(int); out[t]=df
 missing=(set(needed)|{'Filetop'})-set(out)
 if missing: raise ValueError(f'Missing trace categories: {sorted(missing)}')
 return out
def matrix(frames,names):
 labels={t:d.set_index('Package_Name')['Level'] for t,d in frames.items()}
 common=sorted(set.intersection(*(set(s.index) for s in labels.values())))
 if len(common)<100: raise ValueError(f'Only {len(common)} common packages; need 100')
 y0=labels['Filetop'].reindex(common)
 for t,s in labels.items():
  if s.reindex(common).isna().any() or not s.reindex(common).equals(y0): raise ValueError(f'Conflicting labels: {t}')
 y=y0.to_numpy(dtype=int)
 if set(np.unique(y))!={0,1}: raise ValueError('Need both labels 0=benign and 1=malicious')
 idx={t:d.set_index('Package_Name').reindex(common) for t,d in frames.items()}; X=pd.DataFrame(index=common)
 for n in names:
  t,_,c=n.partition('__')
  if t not in idx or c not in idx[t]: raise ValueError(f'Missing feature column: {n}')
  X[n]=pd.to_numeric(idx[t][c],errors='coerce')
 X=X.replace([np.inf,-np.inf],np.nan); empty=list(X.columns[X.isna().all()])
 if empty: raise ValueError('All-missing features: '+', '.join(empty))
 return X,y,common
def metrics(y,p):
 p=np.asarray(p,float)
 if p.ndim!=1 or len(p)!=len(y) or not np.isfinite(p).all() or ((p<0)|(p>1)).any(): raise ValueError('Invalid model probabilities')
 pred=(p>=.5).astype(int)
 return {'accuracy':round(float(accuracy_score(y,pred)),6),'precision_malicious':round(float(precision_score(y,pred,zero_division=0)),6),'recall_malicious':round(float(recall_score(y,pred,zero_division=0)),6),'f1_malicious':round(float(f1_score(y,pred,zero_division=0)),6),'roc_auc':round(float(roc_auc_score(y,p)),6),'confusion_matrix_labels_0_1':confusion_matrix(y,pred,labels=[0,1]).tolist(),'holdout_samples':int(len(y))}
def train(archive,out,schema=SCHEMA):
 out=Path(out).expanduser().resolve()
 if out.exists() and any(out.iterdir()): raise FileExistsError(f'Output directory must be new or empty: {out}')
 archive=Path(archive).expanduser().resolve()
 if not archive.is_file(): raise FileNotFoundError(archive)
 if digest(archive,'md5')!=MD5: raise ValueError('Dataset MD5 mismatch; refusing to train')
 names=names_from(schema); X,y,packages=matrix(read_frames(archive,names),names)
 groups=np.array([re.sub(r'-\d.*$','',str(p)) for p in packages])
 try: tr,te=next(StratifiedGroupKFold(n_splits=5,shuffle=True,random_state=SEED).split(X,y,groups))
 except ValueError as e: raise ValueError(f'Cannot create grouped holdout: {e}') from e
 if set(groups[tr])&set(groups[te]): raise RuntimeError('Package-family leakage detected')
 if set(np.unique(y[tr]))!={0,1} or set(np.unique(y[te]))!={0,1}: raise ValueError('Holdout must include both labels')
 lr=Pipeline([('imputer',SimpleImputer(strategy='median',keep_empty_features=True)),('scale',StandardScaler()),('classifier',LogisticRegression(max_iter=3000,class_weight='balanced',random_state=SEED))])
 rf=Pipeline([('imputer',SimpleImputer(strategy='median',keep_empty_features=True)),('classifier',RandomForestClassifier(n_estimators=300,min_samples_leaf=2,class_weight='balanced_subsample',random_state=SEED,n_jobs=-1))])
 a=X.iloc[tr].to_numpy(float); b=X.iloc[te].to_numpy(float); lr.fit(a,y[tr]); rf.fit(a,y[tr])
 for m in (lr,rf):
  if list(m.classes_)!=[0,1] or m.n_features_in_!=48: raise RuntimeError('Trained model schema/class mismatch')
 p1=lr.predict_proba(b)[:,list(lr.classes_).index(1)]; p2=rf.predict_proba(b)[:,list(rf.classes_).index(1)]
 result={'dataset':'QUT-DV25 processed traces','source_doi':DOI,'license':LICENSE,'evaluation_type':'first StratifiedGroupKFold holdout; package families separated','seed':SEED,'label_mapping':{'0':'benign','1':'malicious'},'feature_count':48,'common_packages':len(packages),'train_samples':len(tr),'holdout_samples':len(te),'models':{'logistic_regression':metrics(y[te],p1),'random_forest':metrics(y[te],p2),'ensemble_mean_probability':metrics(y[te],(p1+p2)/2)},'limitations':['Metrics apply only to held-out QUT-DV25 traces.','Live telemetry parity and real-time detection performance are not established.','Incomplete or integrity-alerted events must remain review-gated.']}
 out.parent.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='tracegate-model-',dir=str(out.parent)) as temp:
  stage=Path(temp)/'artifacts'; stage.mkdir()
  joblib.dump(lr,stage/'logistic_regression.joblib',compress=3); joblib.dump(rf,stage/'random_forest.joblib',compress=3)
  (stage/'feature_names.json').write_text(json.dumps(names,indent=2)+'\n',encoding='utf-8'); (stage/'metrics.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
  for n in ('logistic_regression.joblib','random_forest.joblib'):
   m=joblib.load(stage/n); p=np.asarray(m.predict_proba(b[:min(5,len(b))]),float)
   if list(m.classes_)!=[0,1] or p.shape!=(min(5,len(b)),2) or not np.isfinite(p).all(): raise RuntimeError(f'Serialized model check failed: {n}')
  try: revision=subprocess.run(['git','-C',str(ROOT),'rev-parse','HEAD'],capture_output=True,text=True,timeout=2).stdout.strip() or None
  except (OSError,subprocess.SubprocessError): revision=None
  manifest={'manifest_version':1,'built_at_utc':datetime.now(timezone.utc).isoformat(),'source_revision':revision,'python_version':sys.version.split()[0],'numpy_version':np.__version__,'pandas_version':pd.__version__,'scikit_learn_version':sklearn.__version__,'joblib_version':joblib.__version__,'dataset':{'file_name':archive.name,'md5':MD5,'sha256':digest(archive),'source_doi':DOI,'license':LICENSE},'evaluation':{'seed':SEED,'train_samples':len(tr),'holdout_samples':len(te),'package_group_overlap':0},'artifact_sha256':{n:digest(stage/n) for n in ('logistic_regression.joblib','random_forest.joblib','feature_names.json','metrics.json')},'models_smoke_tested_after_serialization':True,'training_data_is_live_telemetry':False}
  (stage/'training_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
  if out.exists(): out.rmdir()
  os.replace(stage,out)
 print(json.dumps({'output_dir':str(out),'metrics':result,'manifest':manifest},indent=2))
def main():
 p=argparse.ArgumentParser(description=__doc__); p.add_argument('--archive',type=Path,default=Path.home()/'datasets/qut-dv25/QUT-DV25_Datasets.zip'); p.add_argument('--download',action='store_true'); p.add_argument('--output-dir',type=Path,default=Path(os.environ.get('TRACEGATE_ARTIFACT_DIR',str(Path.home()/'tracegate-live/artifacts')))); p.add_argument('--schema',type=Path,default=SCHEMA); a=p.parse_args()
 try:
  archive=a.archive.expanduser()
  if a.download and not archive.exists(): archive=fetch(archive)
  if not archive.is_file(): raise FileNotFoundError(f'Dataset missing: {archive}; use --download to fetch the official archive')
  train(archive,a.output_dir,a.schema); return 0
 except (OSError,ValueError,zipfile.BadZipFile,urllib.error.URLError) as e:
  print(f'TRAINING_BLOCKED: {type(e).__name__}: {e}',file=sys.stderr); return 2
if __name__=='__main__': raise SystemExit(main())
