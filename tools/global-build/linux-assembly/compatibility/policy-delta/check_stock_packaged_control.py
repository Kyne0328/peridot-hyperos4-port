from classify_delta import Policy,source_list,R,H
import json
normal = Policy('stock-normal', R/'stock-runtime-decoded.cil', source_list(H/'stock-policy-control-init-style.status.json'))
packaged = Policy('stock-packaged', R/'stock-packaged-precompiled-decoded.cil', [])
rows = json.loads((R/'mixed-violating-accesses.json').read_text())
changes=[]
for row in rows:
 key=(row['source'],row['target'],row['class'])
 before=normal.access(*key)
 after=packaged.access(*key)
 relevant=set(row['permissions'])
 if (before & relevant) != (after & relevant):
  changes.append({'source':key[0],'target':key[1],'class':key[2], 'only_normal_control':sorted((before-after)&relevant), 'only_packaged_control':sorted((after-before)&relevant)})
result={'scope':'All concrete mixed violating permission tuples, including assertion-alias rows', 'queried_pairs':len(rows), 'normal_and_packaged_stock_agree_for_all_queried_permissions':not changes, 'changes':changes, 'normal_types':len(normal.types), 'packaged_types':len(packaged.types)}
(R/'stock-packaged-control-semantic-comparison.json').write_text(json.dumps(result,indent=2))
print('queries',len(rows),'changed pairs',len(changes))
for row in changes[:20]:print(row)
