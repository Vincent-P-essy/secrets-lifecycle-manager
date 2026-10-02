"""Capture real fixture output and local application interfaces."""
import argparse, json, os, pathlib, re, socket, subprocess, tempfile, time, textwrap
from PIL import Image, ImageDraw, ImageFont
from markdown_it import MarkdownIt
BASE=pathlib.Path.cwd().resolve()
ENV={k:v for k,v in os.environ.items() if not re.search(r"(?i)(token|secret|password|api.?key)",k)}
ENV.update(NO_COLOR="1",TERM="dumb",COLUMNS="100")
files=[]; results=[]
def clean(s):
    s=re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]","",s)
    return s.replace(str(BASE)+"/","").replace(os.environ.get("RUNNER_TEMP","/tmp")+"/","runner-temp/")
def add(p): files.append(str(p.relative_to(BASE)))
def run(p,c):
    c={"args":c} if isinstance(c,list) else c
    directory=(p/c.get("cwd",".")).resolve()
    if directory!=p and p not in directory.parents: raise ValueError("Command directory escapes project")
    args=c["args"]; env=ENV|{"PYTHONPATH":str(directory/"src")+":"+str(directory)}|c.get("env",{})
    try:
        q=subprocess.run(args,cwd=directory,env=env,input=c.get("input"),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=c.get("timeout",240))
        code,output=q.returncode,q.stdout
    except subprocess.TimeoutExpired as e:
        output=e.stdout or ""
        if isinstance(output,bytes): output=output.decode(errors="replace")
        code,output=124,output+"\nCommand timed out."
    except OSError as e: code,output=127,str(e)
    return dict(command=clean(" ".join(args))+(" (in "+c["cwd"]+")" if c.get("cwd") else ""),exit=code,expected_exit=c.get("expected_exit",0),output=clean(output))
def terminal(p,rs,label):
    d=p/"docs/screenshots";d.mkdir(parents=True,exist_ok=True);lines=[label,""]
    for r in rs:
        raw=r["output"].splitlines();lines+=["$ "+r["command"]]+raw[:28]
        if len(raw)>28: lines+=["... excerpt; full output in execution.txt"]+raw[-8:]
        lines+=["Exit status: "+str(r["exit"]),""]
    wrapped=[]
    for line in lines: wrapped+=textwrap.wrap(line,104,replace_whitespace=False,drop_whitespace=False) or [""]
    font=ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",15)
    im=Image.new("RGB",(1024,max(240,44+22*len(wrapped))),"#181818");draw=ImageDraw.Draw(im)
    for i,line in enumerate(wrapped): draw.text((20,20+22*i),line,font=font,fill="#8ccd9c" if line.startswith("$ ") else "#e5e5e5")
    im.save(d/"execution.png",compress_level=9)
    (d/"execution.json").write_text(json.dumps(rs,indent=2)+"\n")
    (d/"execution.txt").write_text("\n\n".join("$ "+r["command"]+"\n"+r["output"]+"\nExit: "+str(r["exit"]) for r in rs)+"\n")
    for name in ["execution.png","execution.json","execution.txt"]: add(d/name)
    return "docs/screenshots/execution.png"
def browser(p,j):
    d=p/"docs/screenshots";d.mkdir(parents=True,exist_ok=True);port=j.get("port",8650);server=None
    with tempfile.TemporaryFile(mode="w+t") as log:
        try:
            if j.get("documentation"):
                source=(p/"README.md").read_text() if (p/"README.md").exists() else j["label"]
                source=re.sub(r"(?s)<!-- execution-capture -->.*?<!-- /execution-capture -->","",source)
                temp=pathlib.Path(tempfile.mkdtemp())
                body=MarkdownIt("commonmark",{"html":False}).render(source)
                (temp/"index.html").write_text('<!doctype html><meta charset="utf-8"><title>'+j["label"]+'</title><style>body{max-width:1040px;margin:44px auto;padding:0 30px;font:19px/1.6 system-ui;color:#24292f}h1{font-size:38px}h2{border-bottom:1px solid #ddd}pre{padding:18px;background:#f6f8fa;white-space:pre-wrap;font:16px/1.6 monospace}img{max-width:100%}a{color:#0969da}</style>'+body)
                command=["python","-m","http.server",str(port),"--bind","127.0.0.1","--directory",str(temp)]
            else: command=j["server"]
            directory=(p/j.get("server_cwd",".")).resolve()
            if directory!=p and p not in directory.parents: raise ValueError("Server directory escapes project")
            server=subprocess.Popen(command,cwd=directory,env=ENV|{"PYTHONPATH":str(p/"src")+":"+str(p)}|j.get("server_env",{}),stdout=log,stderr=log)
            for _ in range(240):
                try:
                    with socket.create_connection(("127.0.0.1",port),.2): break
                except OSError:
                    if server.poll() is not None: raise RuntimeError("Application server stopped before capture")
                    time.sleep(.25)
            else: raise RuntimeError("Application server did not open its local port")
            out=d/"application.png";url="http://127.0.0.1:"+str(port)+j.get("path","/")
            q=subprocess.run(["node",str(BASE/".github/tools/capture-browser.mjs"),url,str(out),json.dumps(j.get("actions",[]))],cwd=p,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120)
            if q.returncode: raise RuntimeError(clean(q.stdout))
            meta=json.loads(pathlib.Path(str(out)+".json").read_text())
            add(out);add(pathlib.Path(str(out)+".json"))
            if meta["errors"]: results.append(dict(root=j["root"],browser_errors=meta["errors"]))
            return "docs/screenshots/application.png",None
        except Exception as e:
            log.seek(0);return None,dict(command="Start local application and capture browser",exit=1,expected_exit=0,output=str(e)+"\n"+clean(log.read()[-12000:]))
        finally:
            if server:
                server.terminate()
                try: server.wait(timeout=5)
                except subprocess.TimeoutExpired: server.kill()
def doc(p,j,rs,images):
    good=all(r["exit"]==r["expected_exit"] for r in rs);caption=j["caption"];tick=chr(96)
    text="# Execution record\n\n"+caption+"\n\n"
    if j.get("documentation"): text+="This image renders the repository documentation in a browser. It does not show an application execution.\n\n"
    for r in rs: text+="- "+tick+r["command"].replace(tick,"'")+tick+" — exit "+str(r["exit"])+" (expected "+str(r["expected_exit"])+").\n"
    if rs: text+="\nThe terminal image renders recorded command output. [Full transcript](screenshots/execution.txt).\n"
    if not good: text+="\nAt least one command failed. This capture does not establish a passing build or test suite.\n"
    text+="\nExternal integrations and production deployment are not covered by these fixtures.\n"
    v=p/"docs/verification.md";v.parent.mkdir(parents=True,exist_ok=True);v.write_text(text);add(v)
    readme=p/"README.md";source=readme.read_text() if readme.exists() else "# "+j["label"]+"\n"
    source=re.sub(r"(?s)<!-- execution-capture -->.*?<!-- /execution-capture -->\s*","",source)
    snippet="<!-- execution-capture -->\n## Execution preview\n\n"+"\n\n".join("!["+j["label"]+"]("+x+")" for x in images)+"\n\n"+caption+" [Verification](docs/verification.md).\n<!-- /execution-capture -->\n\n"
    m=re.search(r"^## ",source,re.M);pos=m.start() if m else len(source)
    readme.write_text(source[:pos].rstrip()+"\n\n"+snippet+source[pos:]);add(readme)
    results.append(dict(root=j["root"],passed_commands=good,images=images))
def main():
    cfg=json.loads((BASE/"docs/capture-config.json").read_text())
    for j in cfg["jobs"]:
        p=(BASE/j["root"]).resolve()
        if p!=BASE and BASE not in p.parents: raise ValueError("Project path escapes repository")
        rs=[];ready=True
        for c in j.get("setup",[]):
            r=run(p,c)
            if r["exit"]!=r["expected_exit"]: rs.append(r);ready=False;break
        if ready:
            for c in j.get("commands",[]): rs.append(run(p,c))
        images=[]
        if ready and (j.get("server") or j.get("documentation")):
            image,error=browser(p,j)
            if image: images.append(image)
            if error: rs.append(error)
        for name in j.get("images",[]):
            if (p/name).exists(): images.append(name);add(p/name)
        for copy in j.get("copies",[]):
            src=p/copy["source"];dst=p/copy["target"]
            if src.exists(): dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(src.read_bytes());add(dst)
        if rs: images.append(terminal(p,rs,j["label"]))
        if not images: images.append(terminal(p,[dict(command="Capture project",exit=1,expected_exit=0,output="No configured capture could be produced.")],j["label"]))
        doc(p,j,rs,images)
    if cfg.get("gallery"):
        rows=["# Project execution gallery","","Real captures and recorded command exit statuses. Failed commands remain visible as failures.","","| Project | Capture | Record |","|---|---|---|"]
        for r in results:
            if "images" not in r: continue
            p=pathlib.PurePosixPath(r["root"]);rows.append("| ["+p.name+"](../"+str(p/"README.md")+") | !["+p.name+"](../"+str(p/r["images"][0])+") | [Execution](../"+str(p/"docs/verification.md")+") |")
        g=BASE/"docs/execution-gallery.md";g.write_text("\n".join(rows)+"\n");add(g)
        rd=BASE/"README.md";s=rd.read_text() if rd.exists() else "# Projects\n"
        if "docs/execution-gallery.md" not in s: rd.write_text(s.rstrip()+"\n\n## Execution gallery\n\n[Captures and verification for every project](docs/execution-gallery.md).\n");add(rd)
    r=BASE/"docs/capture-results.json";r.write_text(json.dumps(results,indent=2)+"\n");add(r)
    (BASE/"docs/capture-files.json").write_text(json.dumps(sorted(set(files)))+"\n")
    print(json.dumps(results,indent=2))
if __name__=="__main__":
    import base64,hashlib
    main()
    for name in sorted(set(files+["docs/capture-files.json"])):
        p=BASE/name
        raw=p.read_bytes()
        sha=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
        print("CAPTURE_BEGIN "+json.dumps(dict(path=name,sha=sha,size=len(raw))),flush=True)
        encoded=base64.b64encode(raw).decode()
        for i in range(0,len(encoded),4096):
            print("CAPTURE_CHUNK "+encoded[i:i+4096],flush=True)
        print("CAPTURE_END",flush=True)
