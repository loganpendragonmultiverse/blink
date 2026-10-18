(() => {
  const toast = (message) => {
    const old = document.querySelector('.toast');
    if (old) old.remove();
    const el = document.createElement('div');
    el.className = 'toast';
    el.setAttribute('role', 'status');
    el.textContent = message;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 2600);
  };
  document.querySelectorAll('[data-share]').forEach((button) => {
    button.addEventListener('click', async () => {
      const url = button.dataset.share;
      try {
        if (navigator.share) await navigator.share({ title: document.title, url });
        else {
          await navigator.clipboard.writeText(url);
          toast('Link copied');
        }
      } catch (error) {
        if (error && error.name !== 'AbortError') toast('Could not share this link');
      }
    });
  });
  document.querySelectorAll('[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });
  const count = (name) => {
    const input = document.querySelector('[name="' + name + '"]');
    const output = document.querySelector('[data-count-for="' + name + '"]');
    if (!input || !output) return;
    const update = () => output.textContent = input.value.length.toLocaleString();
    input.addEventListener('input', update);
    update();
  };
  count('title');
  count('body');
})();
(() => {
  const body = document.querySelector('textarea[name="body"]');
  if (!body) return;
  const escape = text => text.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
  const inline = (text, depth=0) => {
    if (depth > 8) return escape(text);
    const pattern = /https?:\/\/[^\s<>]+|\*\*(?=\S)(.+?)\*\*|__(?=\S)(.+?)__|(?<!\*)\*(?=\S)([^\n]+?)\*(?!\*)/gu;
    let out='', pos=0;
    for (const m of text.matchAll(pattern)) {
      out += escape(text.slice(pos,m.index));
      const token=m[0];
      if (/^https?:\/\//i.test(token)) {
        const url=token.replace(/[.,;:!?)]+$/,'');
        out += '<a href="'+escape(url)+'" target="_blank" rel="ugc nofollow noopener">'+escape(url)+'</a>'+escape(token.slice(url.length));
      } else {
        const tag=token.startsWith('**')?'strong':token.startsWith('__')?'u':'em';
        const n=tag==='em'?1:2;
        out += '<'+tag+'>'+inline(token.slice(n,-n),depth+1)+'</'+tag+'>';
      }
      pos=m.index+token.length;
    }
    return out+escape(text.slice(pos));
  };
  const preview=document.querySelector('[data-body-preview]');
  const details=document.querySelector('.format-preview');
  const update=()=>{ if(details.open) preview.innerHTML=inline(body.value).replace(/\r\n|\r|\n/g,'<br>'); };
  body.addEventListener('input',update); details.addEventListener('toggle',update);
  const format=(marker)=>{
    const start=body.selectionStart,end=body.selectionEnd,text=body.value.slice(start,end);
    if(start>=marker.length && body.value.slice(start-marker.length,start)===marker && body.value.slice(end,end+marker.length)===marker){
      body.setRangeText(text,start-marker.length,end+marker.length,'select');
    } else {
      body.setRangeText(marker+text+marker,start,end,'end');
      body.setSelectionRange(start+marker.length,end+marker.length);
    }
    body.focus();body.dispatchEvent(new Event('input',{bubbles:true}));
  };
  document.querySelectorAll('[data-format]').forEach(button=>{
    button.addEventListener('mousedown',event=>event.preventDefault());
    button.addEventListener('click',()=>format(button.dataset.format));
  });
  body.addEventListener('keydown',event=>{
    if((event.ctrlKey||event.metaKey)&&!event.altKey){
      const marker={b:'**',i:'*',u:'__'}[event.key.toLowerCase()];
      if(marker){event.preventDefault();format(marker);}
    }
  });
})();
