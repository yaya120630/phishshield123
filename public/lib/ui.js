const PHISHSHIELD_TIPS = [
  { title: "Check the domain, not the padlock", text: "A padlock icon only means the connection is encrypted — it says nothing about whether the site itself is genuine. Always read the actual domain name." },
  { title: "Hover before you click", text: "On desktop, hovering over a link shows the real destination in the status bar. If it doesn't match the text or the sender, don't click." },
  { title: "Urgency is a manipulation tactic", text: "Messages that pressure you to act 'immediately' or threaten account suspension are a classic phishing pattern designed to stop you from thinking it through." },
  { title: "Look for lookalike characters", text: "Attackers swap letters for similar-looking ones (like 'rn' for 'm', or a zero for the letter O) in domain names to imitate trusted brands." },
  { title: "Banks won't ask for your full password", text: "Legitimate banks and payment providers never ask you to type your complete password or one-time PIN into a page reached via an email or SMS link." },
  { title: "Bookmark sites you log into often", text: "For banking, email, and payment sites, use a saved bookmark instead of search results or links from messages — it guarantees you land on the real domain." }
];

function phishshieldVerdictColor(verdict) {
  return { danger: "#f87171", warn: "#fbbf24", safe: "#34d399" }[verdict] || "#4c8dff";
}

function phishshieldRenderGauge(container, pct, size = 56, stroke = 5) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const offset = c - (pct / 100) * c;
  const color = phishshieldVerdictColor(pct >= 60 ? "danger" : pct >= 30 ? "warn" : "safe");

  container.innerHTML = `
    <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
      <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="#232d45" stroke-width="${stroke}"/>
      <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${color}" stroke-width="${stroke}"
        stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${c}"
        style="transition: stroke-dashoffset 1s cubic-bezier(.4,0,.2,1);"/>
    </svg>
    <div class="gauge-pct" style="color:${color}">${pct}%</div>
  `;
  requestAnimationFrame(() => {
    const animCircle = container.querySelectorAll("circle")[1];
    if (animCircle) animCircle.setAttribute("stroke-dashoffset", offset);
  });
}

function phishshieldBadge(verdict, risk) {
  const map = { danger: "Phishing", warn: "Suspicious", safe: "Safe" };
  return `<span class="badge ${verdict}">${map[verdict] || verdict} · ${risk}%</span>`;
}

function phishshieldTimeAgo(iso) {
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs} hr ago`;
  const days = Math.floor(hrs / 24);
  if (days === 1) return "Yesterday";
  return `${days} days ago`;
}