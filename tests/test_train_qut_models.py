import json
from pathlib import Path
import numpy as np
import pandas as pd
import pytest
from scripts import train_qut_models as t

SCHEMA=t.names_from(Path(__file__).parents[1]/'data/model_feature_names.json')

def frames(count=100):
 rng=np.random.default_rng(19); package=[f'pkg{i:03d}-1.0' for i in range(count)]; y=np.array([i%2 for i in range(count)],int)
 tags={n.split('__',1)[0] for n in SCHEMA}|{'Pattern'}; out={}
 for tag in tags:
  data={'Package_Name':package,'Level':y}
  for i,name in enumerate(SCHEMA):
   ft,col=name.split('__',1)
   if ft==tag: data[col]=y*2+rng.normal(0,.4,count)+i/100
  out[tag]=pd.DataFrame(data)
 return out

def test_matrix_schema_and_both_labels():
 X,y,p=t.matrix(frames(),SCHEMA); assert list(X.columns)==SCHEMA; assert len(X)==len(y)==len(p)==100; assert set(y)=={0,1}

def test_matrix_rejects_conflicting_labels():
 f=frames(); f['TCP'].loc[0,'Level']=1-int(f['TCP'].loc[0,'Level'])
 with pytest.raises(ValueError,match='Conflicting labels'): t.matrix(f,SCHEMA)

def test_matrix_rejects_all_missing_feature():
 f=frames(); f['Filetop'][SCHEMA[0].split('__',1)[1]]=np.nan
 with pytest.raises(ValueError,match='All-missing features'): t.matrix(f,SCHEMA)

def test_grouped_split_includes_both_classes_without_family_leakage():
 X,y,packages=t.matrix(frames(),SCHEMA); groups=np.array([t.re.sub(r'-\d.*$','',p) for p in packages])
 tr,te=next(t.StratifiedGroupKFold(n_splits=5,shuffle=True,random_state=t.SEED).split(X,y,groups))
 assert not set(groups[tr])&set(groups[te]); assert set(y[tr])==set(y[te])=={0,1}

def test_pipelines_accept_missing_inputs_and_emit_valid_probabilities():
 from sklearn.pipeline import Pipeline
 from sklearn.impute import SimpleImputer
 from sklearn.preprocessing import StandardScaler
 from sklearn.linear_model import LogisticRegression
 from sklearn.ensemble import RandomForestClassifier
 X,y,_=t.matrix(frames(),SCHEMA); X=X.to_numpy(float); X[0,0]=np.nan
 models=(Pipeline([('imputer',SimpleImputer(strategy='median',keep_empty_features=True)),('scale',StandardScaler()),('classifier',LogisticRegression(max_iter=3000,class_weight='balanced',random_state=t.SEED))]), Pipeline([('imputer',SimpleImputer(strategy='median',keep_empty_features=True)),('classifier',RandomForestClassifier(n_estimators=20,min_samples_leaf=2,class_weight='balanced_subsample',random_state=t.SEED,n_jobs=-1))]))
 for model in models:
  model.fit(X,y); p=model.predict_proba(X[:5]); assert p.shape==(5,2); assert np.isfinite(p).all(); assert list(model.classes_)==[0,1]; assert model.n_features_in_==48

def test_metrics_reject_nonfinite_probabilities():
 with pytest.raises(ValueError,match='Invalid model probabilities'): t.metrics(np.array([0,1]),np.array([.2,np.nan]))

def test_model_packaging_roundtrip_is_atomic_and_does_not_overwrite(tmp_path,monkeypatch):
 archive=tmp_path/'fixture.zip'; archive.write_bytes(b'test fixture only')
 monkeypatch.setattr(t,'digest',lambda _path, alg='sha256': t.MD5 if alg=='md5' else 'test-digest')
 monkeypatch.setattr(t,'read_frames',lambda *_:frames())
 out=tmp_path/'artifacts'; t.train(archive,out,Path(__file__).parents[1]/'data/model_feature_names.json')
 for name in t.FILES: assert (out/name).is_file()
 manifest=json.loads((out/'training_manifest.json').read_text())
 assert manifest['models_smoke_tested_after_serialization']; assert manifest['training_data_is_live_telemetry'] is False
 with pytest.raises(FileExistsError,match='must be new or empty'): t.train(archive,out,Path(__file__).parents[1]/'data/model_feature_names.json')
