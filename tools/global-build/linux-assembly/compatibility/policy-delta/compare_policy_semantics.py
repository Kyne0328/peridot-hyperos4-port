from classify_delta import Policy,source_list,R,H
import argparse,json

def canonical(policy):return {(n[1],n[2],n[3][0],tuple(sorted(n[3][1]))) for n,l in policy.allow}
def members(policy,rule):
 s,t,c,p=rule
 return policy.members(s), None if t=='self' else policy.members(t)
def expand(policy,rule):
 s,t=members(policy,rule);c=rule[2]
 return {(a,a,c) for a in s} if t is None else {(a,b,c) for a in s for b in t}
def compare(before,after):
 assert before.types==after.types and before.classes==after.classes and before.alias==after.alias
 br=canonical(before);ar=canonical(after);keys=set();changed_common=0
 for rule in br-ar:keys.update(expand(before,rule))
 for rule in ar-br:keys.update(expand(after,rule))
 for rule in br&ar:
  bs,bt=members(before,rule);ns,nt=members(after,rule);c=rule[2]
  if bs==ns and bt==nt:continue
  changed_common+=1
  if bt is None and nt is None:keys.update((s,s,c) for s in bs^ns)
  else:
   assert bt is not None and nt is not None
   keys.update((s,t,c) for s in bs-ns for t in bt)
   keys.update((s,t,c) for s in ns-bs for t in nt)
   keys.update((s,t,c) for s in bs&ns for t in bt^nt)
 removed=[];added=[]
 for key in sorted(keys):
  b=before.access(*key);a=after.access(*key)
  if b-a:removed.append({'source':key[0],'target':key[1],'class':key[2],'permissions':sorted(b-a)})
  if a-b:added.append({'source':key[0],'target':key[1],'class':key[2],'permissions':sorted(a-b)})
 attr=[]
 for name in sorted(before.attrnames|after.attrnames):
  b=before.members(name) if name in before.attrnames else frozenset();a=after.members(name) if name in after.attrnames else frozenset()
  if a!=b:attr.append({'attribute':name,'members_added':sorted(a-b),'members_removed':sorted(b-a)})
 return {'before':before.label,'after':after.label,'raw_allow_rows_removed':len(br-ar),'raw_allow_rows_added':len(ar-br),'common_allow_rows_with_changed_membership':changed_common,'affected_concrete_pairs_queried':len(keys),'added_permission_tuples':sum(len(x['permissions'])for x in added),'removed_permission_tuples':sum(len(x['permissions'])for x in removed),'added':added,'removed':removed,'attribute_membership_delta':attr,'proof_method':'Exhaustive full-grant queries across the union of changed-rule expansions and all concrete relation symmetric differences of unchanged rules whose memberships change.'}

if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--before',required=True);a.add_argument('--before-status',required=True);a.add_argument('--after',required=True);a.add_argument('--after-status',required=True);a.add_argument('--output',required=True);x=a.parse_args();b=Policy('before',x.before,source_list(x.before_status));n=Policy('after',x.after,source_list(x.after_status));r=compare(b,n);open(x.output,'w').write(json.dumps(r,indent=2));print(json.dumps({k:v for k,v in r.items() if k not in ['added','removed','attribute_membership_delta']},indent=2));print('attribute_changes',len(r['attribute_membership_delta']))
