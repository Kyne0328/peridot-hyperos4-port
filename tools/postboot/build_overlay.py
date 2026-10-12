"""Build a narrow static product overlay against the exact booted framework."""
from pathlib import Path
import hashlib,json,os,subprocess
from cryptography.hazmat.primitives import serialization

ROOT=Path(__file__).resolve().parents[2];WORK=ROOT/'builder/work/postboot-20261004'
OUT=WORK/'overlay';OUT.mkdir(exist_ok=True)
res=OUT/'res/values';res.mkdir(parents=True,exist_ok=True)
manifest='''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.peridot.port.postbootfix.v1">
<uses-sdk android:minSdkVersion="30" android:targetSdkVersion="37"/>
<overlay android:targetPackage="android" android:isStatic="true" android:priority="1002"/>
<application android:hasCode="false" android:label="F6 launcher and display configuration"/>
</manifest>
'''
values='''<resources>
<string name="config_recentsComponentName" translatable="false">com.miui.home/com.miui.home.recents.RecentsActivity</string>
<string name="config_secondaryHomePackage" translatable="false">com.miui.home</string>
<dimen name="rounded_corner_radius">20dp</dimen>
<dimen name="rounded_corner_radius_top">20dp</dimen>
<dimen name="rounded_corner_radius_bottom">20dp</dimen>
</resources>
'''
(OUT/'AndroidManifest.xml').write_text(manifest,encoding='utf-8');(res/'config.xml').write_text(values,encoding='utf-8')
tools=Path(os.environ['LOCALAPPDATA'])/'Android/Sdk/build-tools/37.0.0'
signing=json.loads((ROOT/'builder/work/installer-ri5-recoveryfix-20261004/signing-public.json').read_text())
key_path=ROOT/signing['private_key_path'];cert=ROOT/signing['certificate_path']
key=serialization.load_pem_private_key(key_path.read_bytes(),None);pk8=key_path.parent/'private-pkcs8.der'
if not pk8.exists():
 with pk8.open('xb') as f:f.write(key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
commands=[]
def run(command):
 p=subprocess.run(list(map(str,command)),capture_output=True,text=True)
 commands.append({'argv':list(map(str,command)),'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
 assert p.returncode==0,p.stderr+p.stdout
 return p.stdout
run([tools/'aapt2.exe','compile','--dir',OUT/'res','-o',OUT/'compiled.zip'])
run([tools/'aapt2.exe','link','-I',WORK/'framework-res.apk','--manifest',OUT/'AndroidManifest.xml','--auto-add-overlay','-o',OUT/'unsigned.apk',OUT/'compiled.zip'])
# apksigner is a Java tool; invoke its jar directly to preserve structured paths.
java=Path('C:/Program Files/Android/Android Studio/jbr/bin/java.exe')
if not java.exists():java=Path('java')
run([java,'-jar',tools/'lib/apksigner.jar','sign','--key',pk8,'--cert',cert,'--out',OUT/'F6PostBootFix.apk',OUT/'unsigned.apk'])
run([java,'-jar',tools/'lib/apksigner.jar','verify','--verbose',OUT/'F6PostBootFix.apk'])
resources=run([tools/'aapt2.exe','dump','resources',OUT/'F6PostBootFix.apk'])
assert 'com.miui.home/com.miui.home.recents.RecentsActivity' in resources and resources.count('20.000000dp')==3
result={'apk':str(OUT/'F6PostBootFix.apk'),'sha256':hashlib.sha256((OUT/'F6PostBootFix.apk').read_bytes()).hexdigest(),
 'changes':['Recents component package','secondary home package','rounded corner radius/top/bottom'],
 'corner_source':'Live exact F6 ODM overlay reports 20dp; active donor overlay reports 190px',
 'target_framework_sha256':hashlib.sha256((WORK/'framework-res.apk').read_bytes()).hexdigest(),'commands':commands,'runtime_activated':False}
(OUT/'VALIDATION.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:result[k] for k in ['apk','sha256','changes']},indent=2))
