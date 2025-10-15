export function renderSeverityChart(el, counts){
  el.innerHTML = '';
  const total = Object.values(counts).reduce((a,b)=>a+b,0) || 1;
  const svg = createSVG(el, 360, 180);
  const severities = ['Critical','High','Medium','Low'];
  const xStep = 80;
  severities.forEach((s, i) => {
    const v = counts[s] || 0;
    const h = (v/total) * 140;
    const x = 30 + i*xStep;
    const y = 160 - h;
    const rect = rectEl(x, y, 50, h, sevColor(s));
    svg.appendChild(rect);
    svg.appendChild(textEl(x+25, 170, s, 'middle', '10px'));
    svg.appendChild(textEl(x+25, y-6, String(v), 'middle', '12px'));
  });
  el.appendChild(svg);
}

export function renderTypeChart(el, byType){
  el.innerHTML='';
  const entries = Object.entries(byType);
  const total = entries.reduce((a,[,v])=>a+v,0) || 1;
  const svg = createSVG(el, 360, 180);
  const center = { x: 180, y: 90, r: 60 };
  let start = 0;
  entries.forEach(([k,v]) => {
    const angle = (v/total) * Math.PI*2;
    const end = start + angle;
    const path = donutSlice(center.x, center.y, center.r, center.r+20, start, end);
    const p = document.createElementNS('http://www.w3.org/2000/svg','path');
    p.setAttribute('d', path);
    p.setAttribute('fill', hashColor(k));
    p.setAttribute('opacity', '0.9');
    svg.appendChild(p);
    const mid = (start+end)/2;
    const lx = center.x + Math.cos(mid)*(center.r+30);
    const ly = center.y + Math.sin(mid)*(center.r+30);
    svg.appendChild(textEl(lx, ly, `${k} (${v})`, 'middle', '10px'));
    start = end;
  });
  el.appendChild(svg);
}

function createSVG(el, w, h){
  const svg = document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
  svg.style.width='100%'; svg.style.height='100%';
  return svg;
}
function rectEl(x,y,w,h,fill){
  const r = document.createElementNS('http://www.w3.org/2000/svg','rect');
  r.setAttribute('x',x); r.setAttribute('y',y); r.setAttribute('width',w); r.setAttribute('height',h);
  r.setAttribute('rx',4); r.setAttribute('fill',fill);
  return r;
}
function textEl(x,y,t,anchor='start',size='12px'){
  const tx = document.createElementNS('http://www.w3.org/2000/svg','text');
  tx.setAttribute('x',x); tx.setAttribute('y',y); tx.setAttribute('text-anchor',anchor);
  tx.setAttribute('font-size',size); tx.textContent=t;
  return tx;
}
function sevColor(s){
  switch(s){
    case 'Critical': return '#b91c1c';
    case 'High': return '#ef4444';
    case 'Medium': return '#f59e0b';
    case 'Low': return '#10b981';
    default: return '#64748b';
  }
}
function donutSlice(cx, cy, r1, r2, a0, a1){
  const p = (r,a)=>[cx + Math.cos(a)*r, cy + Math.sin(a)*r];
  const [x0,y0] = p(r2,a0), [x1,y1]=p(r2,a1), [x2,y2]=p(r1,a1), [x3,y3]=p(r1,a0);
  const large = (a1-a0) > Math.PI ? 1 : 0;
  return `M ${x0} ${y0} A ${r2} ${r2} 0 ${large} 1 ${x1} ${y1} L ${x2} ${y2} A ${r1} ${r1} 0 ${large} 0 ${x3} ${y3} Z`;
}
function hashColor(str){
  let h=0; for(let i=0;i<str.length;i++) h = Math.imul(31,h) + str.charCodeAt(i) | 0;
  const r = (h>>16)&255, g=(h>>8)&255, b=h&255;
  return `rgb(${(r+256)%256}, ${(g+256)%256}, ${(b+256)%256})`;
}
