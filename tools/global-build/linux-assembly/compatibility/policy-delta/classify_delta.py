#!/usr/bin/env python3
"""Resolve reported neverallow assertions to concrete normal-policy access tuples.
No policy writes or installation. Binary policy decoding uses isolated libsepol.
"""
from pathlib import Path
from collections import defaultdict,Counter
from functools import lru_cache
import hashlib,json,re
R=Path(__file__).resolve().parent;H=R.parent

def parse(s):
 stack=[];root=None
 for t in re.findall(r'\(|\)|[^\s()]+',s):
  if t=='(':
   x=[]
   if stack:stack[-1].append(x)
   stack.append(x)
  elif t==')':
   if not stack:raise ValueError('unbalanced')
   x=stack.pop()
   if not stack:
    if root is not None:raise ValueError('multiple expressions')
    root=x
  else:
   if not stack:raise ValueError('token outside expression')
   stack[-1].append(t)
 if stack or root is None:raise ValueError('incomplete expression')
 return root

def load(path,kinds):
 out=[]
 for no,line in enumerate(Path(path).read_text().splitlines(),1):
  if line.startswith('(') and line.split(' ',1)[0][1:] in kinds:out.append((parse(line),{'file':str(path),'line':no,'expression':line}))
 return out

class Policy:
 def __init__(self,label,binary_cil,source_files):
  self.label=label;self.source_files=source_files;self.types=set();self.attrnames=set();self.compdefs={};self.source_defs=defaultdict(list);self.alias={};self.allow=[];self.source_allow=[];self.classes=set();self.permission_origins=defaultdict(set)
  for node,loc in load(binary_cil,{'type','typeattribute','typeattributeset','typealiasactual','allow','class','booleanif'}):
   kind=node[0]
   if kind=='type':self.types.add(node[1])
   elif kind=='typeattribute':self.attrnames.add(node[1])
   elif kind=='typeattributeset':self.compdefs[node[1]]=node[2]
   elif kind=='typealiasactual':self.alias[node[1]]=node[2]
   elif kind=='class':self.classes.add(node[1])
   elif kind=='allow':self.allow.append((node,loc))
   else:raise ValueError('conditional policy requires explicit interpretation')
  for path in source_files:
   for node,loc in load(path,{'typeattribute','typeattributeset','typealiasactual','allow'}):
    if node[0]=='typeattribute':self.attrnames.add(node[1])
    elif node[0]=='typeattributeset':self.source_defs[node[1]].append(node[2])
    elif node[0]=='typealiasactual':self.alias[node[1]]=node[2]
    elif node[0]=='allow':self.source_allow.append((node,loc))
  self.cache={};self.active=set();self.index=self.make_index(self.allow);self.source_index=self.make_index(self.source_allow)
 def expr(self,x):
  if isinstance(x,str):return self.members(x)
  if not x:return frozenset()
  if x[0]=='all':return frozenset(self.types)
  if x[0]=='not':
   if len(x)!=2:raise ValueError('not arity')
   return frozenset(self.types)-self.expr(x[1])
  if x[0] in ['and','or','xor']:
   vs=[self.expr(v) for v in x[1:]]
   if not vs:raise ValueError('empty operator')
   out=vs[0]
   for v in vs[1:]:out=out&v if x[0]=='and' else out|v if x[0]=='or' else out^v
   return out
  return frozenset().union(*(self.expr(v) for v in x))
 def members(self,name):
  if name in self.types:return frozenset([name])
  if name in self.alias:return self.members(self.alias[name])
  if name in self.cache:return self.cache[name]
  if name in self.active:raise ValueError('cyclic attribute '+name)
  self.active.add(name)
  if name in self.compdefs:out=self.expr(self.compdefs[name])
  elif name in self.source_defs:out=frozenset().union(*(self.expr(x) for x in self.source_defs[name]))
  elif name in self.attrnames:out=frozenset()
  else:raise ValueError('unknown type/attribute '+name)
  self.active.remove(name);self.cache[name]=out;return out
 def make_index(self,rows):
  out=defaultdict(list)
  for node,loc in rows:
   _,src,tgt,cp=node
   if not isinstance(cp,list) or len(cp)!=2 or not isinstance(cp[1],list):raise ValueError('unsupported class-permission expression '+str(node))
   cls,perms=cp;ss=self.members(src);tt=None if tgt=='self' else self.members(tgt);pp=frozenset(perms)
   for s in ss:out[cls,s].append((tt,pp,loc))
  return out
 @lru_cache(maxsize=None)
 def access(self,s,t,c):
  return frozenset().union(*(p for ts,p,loc in self.index.get((c,s),[]) if (t==s if ts is None else t in ts)))
 def origins(self,s,t,c,perms):
  return [{**loc,'matching_permissions':sorted(p&set(perms))} for ts,p,loc in self.source_index.get((c,s),[]) if (t==s if ts is None else t in ts) and p&set(perms)]
 def violations(self,assertions):
  grants=defaultdict(set);origins=defaultdict(list);rec=[]
  for ix,a in enumerate(assertions):
   node=parse(a['rule']);_,src,tgt,cp=node;cls,pp=cp;forbid=set(pp);ss=self.members(src);tt=None if tgt=='self' else self.members(tgt);own=defaultdict(set)
   for s in ss:
    for ats,ap,loc in self.index.get((cls,s),[]):
     p=ap&forbid
     if not p:continue
     available=frozenset([s]) if ats is None else ats;wanted=frozenset([s]) if tt is None else tt
     for t in available&wanted:own[s,t,cls]|=p
   rec.append({'index':ix,'location':a['location'],'rule':a['rule'],'concrete_pairs':len(own),'concrete_permission_tuples':sum(map(len,own.values()))})
   if not own:raise ValueError('compiler failure not reproduced by tuple analysis: '+str(rec[-1]))
   for key,perms in own.items():
    grants[key]|=perms;origins[key].append(ix)
    for perm in perms:self.permission_origins[key+(perm,)].add(ix)
  return grants,origins,rec

def source_list(status):
 j=json.loads(Path(status).read_text());return [x for x in j['command'] if x.endswith('.cil')]
def serialize(rows,policy,assertions,origins):
 out=[]
 for (s,t,c),perms in sorted(rows.items()):
  out.append({'source':s,'target':t,'class':c,'permissions':sorted(perms),'assertion_indices':origins[s,t,c],'permission_assertions':{p:sorted(policy.permission_origins[s,t,c,p]) for p in perms},'source_allow_rules':policy.origins(s,t,c,perms)})
 return out

def main():
 logs=json.loads((H/'neverallow-comparison.json').read_text());policies={}
 for label,statfile in [('mixed',H/'final-global-v2/final-selinux-init-style.status.json'),('stock',H/'stock-policy-control-init-style.status.json')]:
  policies[label]=Policy(label,R/(label+'-runtime-decoded.cil'),source_list(statfile));print(label,'types',len(policies[label].types),'compiled allow rules',len(policies[label].allow),'source allows',len(policies[label].source_allow),flush=True)
 m,s=policies['mixed'],policies['stock'];ma=logs['selinux-additional-neverallow']['constraints'];sa=logs['stock-policy-control-neverallow']['constraints'];mg,mo,mr=m.violations(ma);sg,so,sr=s.violations(sa)
 write=lambda n,o:(R/n).write_text(json.dumps(o,indent=2)+'\n')
 write('mixed-violating-accesses.json',serialize(mg,m,ma,mo));write('stock-violating-accesses.json',serialize(sg,s,sa,so));write('mixed-assertion-expansion.json',mr);write('stock-assertion-expansion.json',sr)
 counts=Counter();delta=[];pcc=[]
 for key,perms in sorted(mg.items()):
  src,tgt,cls=key;base_allowed=s.access(*key);base_viol=sg.get(key,set());parts={'baseline_also_violating':perms&base_viol,'preexisting_access_newly_reported':(perms&base_allowed)-base_viol,'new_mixed_access':perms-base_allowed}
  for category,p in parts.items():
   if not p:continue
   subtype='existing_source_target_class'
   if src not in s.types:subtype='new_source_type'
   elif tgt not in s.types:subtype='new_target_type'
   elif cls not in s.classes:subtype='new_object_class'
   counts[category]+=len(p);rec={'category':category,'subtype':subtype,'source':src,'target':tgt,'class':cls,'permissions':sorted(p),'assertion_indices':mo[key],'permission_assertions':{perm:sorted(m.permission_origins[key+(perm,)]) for perm in p},'source_allow_rules':m.origins(*key,p)};delta.append(rec)
   if src=='pcc_component':pcc.append(rec)
 new=[x for x in delta if x['category']=='new_mixed_access'];summary={'method':'Concrete allow tuples decoded from normal host-compiled policy binaries with isolated upstream libsepol 3.11; type/attribute members from decoded policy, neverallow-only generated sets resolved from exact CIL unions/expressions. Every reported failed assertion must produce at least one actual violating tuple. Historical stderr allow lists are not used as exhaustive evidence because the compiler truncates them.','mixed_failed_assertions':len(ma),'stock_failed_assertions':len(sa),'mixed_unique_access_pairs':len(mg),'mixed_permission_tuples':sum(map(len,mg.values())),'stock_unique_access_pairs':len(sg),'stock_permission_tuples':sum(map(len,sg.values())),'deduplicated_delta_permission_counts':dict(counts),'new_access_pair_records':len(new),'new_access_source_types':dict(Counter(x['source'] for x in new)),'source_hashes':{p:digest(p) for pol in policies.values() for p in pol.source_files},'runtime_policy_binary_hashes':{'mixed':digest(H/'final-global-v2/compiled-policy-offline-only'),'stock':digest(H/'control-compiled-policy-offline-only')},'runtime_constraint_limit':'These are kernel type-enforcement allow permissions, not proof that a process executes, can reach a target, or passes MLS/constraints/DAC/runtime checks.'}
 write('delta-accesses.json',delta);write('pcc-accesses.json',pcc);write('delta-summary.json',summary);print(json.dumps({k:v for k,v in summary.items() if k not in ['source_hashes','runtime_policy_binary_hashes']},indent=2))

def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
if __name__=='__main__':main()
