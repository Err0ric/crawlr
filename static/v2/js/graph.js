// Topology graph (D3). Ported from the classic UI; token names mapped to v2.
// Exports renderGraph(container, collected, target). Requires window.d3.
const MONO = "IBM Plex Mono, ui-monospace, Menlo, monospace";
function _css(prop) { return getComputedStyle(document.documentElement).getPropertyValue(prop).trim(); }

  function renderAsnGraph(container, data, target) {
    const colorASN = '#a855f7', colorV4 = '#d97706', colorV6 = '#14b8a6';
    const v4 = (data.prefixes_v4 || []).slice(0, 40);
    const v6 = (data.prefixes_v6 || []).slice(0, 20);
    const orgLabel = data.org ? `${data.asn} — ${data.org}` : data.asn;

    function prefixSize(cidr) {
      const m = cidr.match(/\/(\d+)$/);
      if (!m) return 1;
      const bits = parseInt(m[1], 10);
      const isV6 = cidr.includes(':');
      if (isV6) return Math.max(Math.min((128 - bits) / 48, 1), 0.3);
      return Math.max(Math.min((32 - bits) / 16, 1), 0.3);
    }
    function ipCount(cidr) {
      const m = cidr.match(/\/(\d+)$/);
      if (!m) return '';
      const bits = parseInt(m[1], 10);
      const isV6 = cidr.includes(':');
      if (isV6) { const n = 128 - bits; return n > 64 ? `2^${n}` : (n > 32 ? `2^${n}` : Math.pow(2, n).toLocaleString()); }
      return Math.pow(2, 32 - bits).toLocaleString();
    }

    const rect = container.getBoundingClientRect();
    const W = Math.max(rect.width || 900, 920);

    // Layout: lane 0 = ASN center, lane 1 = IPv4, lane 2 = IPv6
    const laneX = [60, 320, 320];
    const boxH = 30, gapY = 6, startY = 80;
    const centerW = 240, prefixW = 220;
    const minBoxW = 120, maxBoxW = 220;

    const totalRows = Math.max(v4.length, v6.length, 1);
    const v6StartY = startY + v4.length * (boxH + gapY) + (v4.length > 0 && v6.length > 0 ? 50 : 0);
    const totalH = Math.max(v6StartY + v6.length * (boxH + gapY) + 80, rect.height || 500);

    // Center node Y = midpoint of all content
    const contentBottom = v6.length > 0 ? v6StartY + v6.length * (boxH + gapY) : startY + v4.length * (boxH + gapY);
    const centerY = startY + (contentBottom - startY) / 2 - boxH / 2;

    const svg = d3.select(container).append('svg')
      .attr('width', W).attr('height', totalH)
      .style('background', _css('--bg'));
    const g = svg.append('g');
    svg.call(d3.zoom().scaleExtent([0.3, 4]).on('zoom', (e) => g.attr('transform', e.transform)));

    // Legend
    const legend = g.append('g').attr('transform', 'translate(60, 20)');
    const legendItems = [
      { label: 'ASN', color: colorASN }, { label: 'IPv4 Prefix', color: colorV4 }, { label: 'IPv6 Prefix', color: colorV6 },
    ];
    legendItems.forEach((item, i) => {
      const lg = legend.append('g').attr('transform', `translate(${i * 120}, 0)`);
      lg.append('rect').attr('width', 10).attr('height', 10).attr('rx', 2).attr('fill', item.color).attr('opacity', 0.8);
      lg.append('text').attr('x', 14).attr('y', 9).text(item.label)
        .attr('fill', _css('--ink-3')).attr('font-family', MONO).attr('font-size', '11px');
    });

    // Draw center ASN node
    const cg = g.append('g').attr('transform', `translate(${laneX[0]}, ${centerY})`);
    cg.append('rect').attr('width', centerW).attr('height', 44).attr('rx', 4)
      .attr('fill', 'rgba(124,58,237,0.14)').attr('stroke', colorASN).attr('stroke-width', 2).attr('stroke-opacity', 0.9);
    const asnLabel = data.asn || target;
    cg.append('text').attr('x', centerW / 2).attr('y', 18).attr('text-anchor', 'middle')
      .attr('fill', _css('--ink')).attr('font-family', MONO).attr('font-size', '13px').attr('font-weight', '600')
      .text(asnLabel);
    if (data.org) {
      const orgTrunc = data.org.length > 28 ? data.org.slice(0, 27) + '…' : data.org;
      cg.append('text').attr('x', centerW / 2).attr('y', 34).attr('text-anchor', 'middle')
        .attr('fill', _css('--ink-3')).attr('font-family', MONO).attr('font-size', '11px')
        .text(orgTrunc);
    }

    const tooltip = d3.select(container).append('div').attr('class', 'graph-tooltip').style('display', 'none');
    const centerRight = laneX[0] + centerW;
    const centerMidY = centerY + 22;

    // IPv4 section label
    if (v4.length > 0) {
      g.append('text').attr('x', laneX[1]).attr('y', startY - 12)
        .text(`// IPv4 PREFIXES (${data.prefixes_v4.length})`)
        .attr('fill', colorV4).attr('font-family', MONO).attr('font-size', '11px').attr('letter-spacing', '1px').attr('opacity', 0.7);
    }

    // Draw IPv4 nodes
    v4.forEach((prefix, i) => {
      const y = startY + i * (boxH + gapY);
      const scale = prefixSize(prefix);
      const bw = minBoxW + (maxBoxW - minBoxW) * scale;
      const count = ipCount(prefix);

      // Bezier link
      const x1 = centerRight, y1 = centerMidY;
      const x2 = laneX[1], y2 = y + boxH / 2;
      const mx = (x1 + x2) / 2;
      g.append('path')
        .attr('d', `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`)
        .attr('fill', 'none').attr('stroke', colorV4).attr('stroke-opacity', 0.3).attr('stroke-width', 1 + scale);

      const ng = g.append('g').attr('transform', `translate(${laneX[1]}, ${y})`);
      ng.append('rect').attr('width', bw).attr('height', boxH).attr('rx', 3)
        .attr('fill', 'rgba(217,119,6,0.08)').attr('stroke', colorV4).attr('stroke-width', 1).attr('stroke-opacity', 0.5);
      ng.append('text').attr('x', 8).attr('y', boxH / 2 + 4)
        .attr('fill', '#f59e0b').attr('font-family', MONO).attr('font-size', '12px')
        .text(prefix);
      if (count) {
        ng.append('text').attr('x', bw - 6).attr('y', boxH / 2 + 3).attr('text-anchor', 'end')
          .attr('fill', _css('--ink-3')).attr('font-family', MONO).attr('font-size', '10px')
          .text(count + ' IPs');
      }
      ng.on('mouseover', () => tooltip.style('display', 'block').text(`${prefix} — ${count} IPs`))
        .on('mousemove', (e) => tooltip.style('left', (e.offsetX + 14) + 'px').style('top', (e.offsetY - 10) + 'px'))
        .on('mouseout', () => tooltip.style('display', 'none'));
    });

    // IPv6 separator and label
    if (v6.length > 0) {
      if (v4.length > 0) {
        g.append('line').attr('x1', laneX[1] - 20).attr('x2', laneX[1] + maxBoxW + 20)
          .attr('y1', v6StartY - 28).attr('y2', v6StartY - 28)
          .attr('stroke', _css('--line')).attr('stroke-dasharray', '4,4');
      }
      g.append('text').attr('x', laneX[1]).attr('y', v6StartY - 12)
        .text(`// IPv6 PREFIXES (${data.prefixes_v6.length})`)
        .attr('fill', colorV6).attr('font-family', MONO).attr('font-size', '11px').attr('letter-spacing', '1px').attr('opacity', 0.7);
    }

    // Draw IPv6 nodes
    v6.forEach((prefix, i) => {
      const y = v6StartY + i * (boxH + gapY);
      const scale = prefixSize(prefix);
      const bw = minBoxW + (maxBoxW - minBoxW) * scale;
      const count = ipCount(prefix);

      const x1 = centerRight, y1 = centerMidY;
      const x2 = laneX[2], y2 = y + boxH / 2;
      const mx = (x1 + x2) / 2;
      g.append('path')
        .attr('d', `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`)
        .attr('fill', 'none').attr('stroke', colorV6).attr('stroke-opacity', 0.3).attr('stroke-width', 1 + scale);

      const ng = g.append('g').attr('transform', `translate(${laneX[2]}, ${y})`);
      ng.append('rect').attr('width', bw).attr('height', boxH).attr('rx', 3)
        .attr('fill', 'rgba(20,184,166,0.08)').attr('stroke', colorV6).attr('stroke-width', 1).attr('stroke-opacity', 0.5);
      ng.append('text').attr('x', 8).attr('y', boxH / 2 + 4)
        .attr('fill', '#14b8a6').attr('font-family', MONO).attr('font-size', '11px')
        .text(prefix.length > 26 ? prefix.slice(0, 25) + '…' : prefix);
      if (count) {
        ng.append('text').attr('x', bw - 6).attr('y', boxH / 2 + 3).attr('text-anchor', 'end')
          .attr('fill', _css('--ink-3')).attr('font-family', MONO).attr('font-size', '10px')
          .text(count + ' IPs');
      }
      ng.on('mouseover', () => tooltip.style('display', 'block').text(`${prefix} — ${count} IPs`))
        .on('mousemove', (e) => tooltip.style('left', (e.offsetX + 14) + 'px').style('top', (e.offsetY - 10) + 'px'))
        .on('mouseout', () => tooltip.style('display', 'none'));
    });

    // Stats summary at bottom
    const statsY = totalH - 40;
    const stats = g.append('g').attr('transform', `translate(60, ${statsY})`);
    const statItems = [];
    if (data.rir) statItems.push(`RIR: ${data.rir}`);
    if (data.country) statItems.push(`Country: ${data.country}`);
    if (data.date_registered) statItems.push(`Registered: ${data.date_registered}`);
    statItems.push(`${(data.prefixes_v4 || []).length} IPv4 + ${(data.prefixes_v6 || []).length} IPv6 prefixes`);
    if (data.total_peers) statItems.push(`${data.total_peers} peers`);
    stats.append('text').attr('y', 0)
      .attr('fill', _css('--ink-4')).attr('font-family', MONO).attr('font-size', '11px')
      .text(statItems.join('  ·  '));
  }

  // Cloudflare IP detection (matching backend CIDR ranges)
  const _CF_RANGES = [
    [0xADF53000, 0xFFFFF000], [0x6715F400, 0xFFFFFC00], [0x6716C800, 0xFFFFFC00],
    [0x671F0400, 0xFFFFFC00], [0x8D654000, 0xFFFFC000], [0x6CA2C000, 0xFFFFC000],
    [0xBE5DF000, 0xFFFFF000], [0xBC726000, 0xFFFFF000], [0xC5EAF000, 0xFFFFFC00],
    [0xC6298000, 0xFFFE0000], [0xA29E0000, 0xFFFE0000], [0x68100000, 0xFFF80000],
    [0x68180000, 0xFFFC0000], [0xAC400000, 0xFFF80000], [0x83004800, 0xFFFFFC00],
  ];
  function _isCfIp(ipStr) {
    const parts = ipStr.split('.');
    if (parts.length !== 4) return false;
    const num = ((+parts[0]) << 24 | (+parts[1]) << 16 | (+parts[2]) << 8 | (+parts[3])) >>> 0;
    return _CF_RANGES.some(([net, mask]) => (num & mask) === net);
  }


  export function renderGraph(container, reconCollected, target) {
    container.innerHTML = '';
    const emptyMsg = (msg) => { container.innerHTML = `<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--ink-4);font-family:var(--mono);font-size:12px;">${msg}</div>`; };
    if (typeof d3 === 'undefined') { emptyMsg('D3.js failed to load'); return; }
    const d = reconCollected;
    if (!target || !d || Object.keys(d).length === 0) { emptyMsg('Run a recon scan first'); return; }

    if (/^AS\d+$/i.test(target) && d.asn_detail) { renderAsnGraph(container, d.asn_detail, target); return; }

    const colorMap = { domain: '#a855f7', a: '#a855f7', mx: '#d97706', ns: '#14b8a6', subdomain: '#7c3aed', ip: '#6b7280', asn: '#4b5563', cname: '#8b5cf6', cf_ip: '#f59e0b' };
    const asnInfo = d.asn || {};

    // Build hierarchical tree data
    const treeNodes = []; // {id, label, type, lane, row}
    const treeLinks = []; // {source, target, type}
    const idSet = {};
    let rowCounters = { 1: 0, 2: 0, 3: 0 }; // per-lane row counters
    let subRow = 0;

    function addN(id, label, type, lane) {
      if (idSet[id]) return;
      idSet[id] = true;
      const row = (lane <= 3) ? rowCounters[lane]++ : 0;
      treeNodes.push({ id, label, type, lane, row });
    }
    function addL(src, tgt, type) { treeLinks.push({ source: src, target: tgt, type }); }

    // Lane 0: Domain
    addN(target, target, 'domain', 0);

    // Lane 1: Record type groups + Lane 2: values
    if (d.dns && d.dns.records) {
      const aRecs = d.dns.records['A'] || [];
      for (const ip of aRecs) {
        const rid = 'a_rec_' + ip;
        addN(rid, 'A', 'a', 1);
        addL(target, rid, 'a');
        addN(ip, ip, 'ip', 2);
        addL(rid, ip, 'a');
        if (asnInfo.asn) {
          const aid = 'asn_' + ip;
          addN(aid, `${asnInfo.asn} ${(asnInfo.org || '').slice(0, 30)}`, 'asn', 3);
          addL(ip, aid, 'asn');
        }
      }
      const mxRecs = d.dns.records['MX'] || [];
      for (const mx of mxRecs) {
        const clean = mx.replace(/^\d+\s+/, '').replace(/\.$/, '');
        const mid = 'mx_' + clean;
        addN(mid, 'MX', 'mx', 1);
        addL(target, mid, 'mx');
        const vid = 'mxv_' + clean;
        addN(vid, clean, 'ip', 2);
        addL(mid, vid, 'mx');
      }
      const nsRecs = d.dns.records['NS'] || [];
      for (const ns of nsRecs) {
        const clean = ns.replace(/\.$/, '');
        const nid = 'ns_' + clean;
        addN(nid, 'NS', 'ns', 1);
        addL(target, nid, 'ns');
        const vid = 'nsv_' + clean;
        addN(vid, clean, 'ip', 2);
        addL(nid, vid, 'ns');
      }
      const cnRecs = d.dns.records['CNAME'] || [];
      for (const cn of cnRecs) {
        const clean = cn.replace(/\.$/, '');
        const cid = 'cn_' + clean;
        addN(cid, 'CNAME', 'cname', 1);
        addL(target, cid, 'cname');
        const vid = 'cnv_' + clean;
        addN(vid, clean, 'ip', 2);
        addL(cid, vid, 'cname');
      }
    }

    // Subdomains below main records
    const subNodes = [];
    if (d.subdomains && d.subdomains.subdomains) {
      for (const s of d.subdomains.subdomains.slice(0, 25)) {
        const sid = 'sub_' + s.subdomain;
        subNodes.push({ id: sid, label: s.subdomain, type: 'subdomain', ips: s.ips || [] });
        addL(target, sid, 'sub');
      }
    }

    if (treeNodes.length <= 1 && subNodes.length === 0) { emptyMsg('No graph data — run a recon scan first'); return; }

    const rect = container.getBoundingClientRect();
    const W = rect.width || 900;

    // Layout params
    const laneX = [60, 220, 440, 680];
    const boxH = 28, gapY = 8, startY = 70;
    const subBoxH = 24, subGapY = 4;
    const domainBoxW = 150, typeBoxW = 50, valBoxW = 180, asnBoxW = 200, subBoxW = 160;
    const boxWidths = [domainBoxW, typeBoxW, valBoxW, asnBoxW];

    // Assign positions
    const positions = {};
    // Track lane positions
    const laneRows = [0, 0, 0, 0];

    // Domain node center
    const mainH = Math.max(rowCounters[1], rowCounters[2], rowCounters[3]) * (boxH + gapY);
    positions[target] = { x: laneX[0], y: startY + mainH / 2 };

    // Position lane nodes in order they appear in treeLinks from domain
    const lane1Order = [], lane2Order = [], lane3Order = [];
    for (const n of treeNodes) {
      if (n.lane === 1) lane1Order.push(n);
      if (n.lane === 2) lane2Order.push(n);
      if (n.lane === 3) lane3Order.push(n);
    }
    lane1Order.forEach((n, i) => { positions[n.id] = { x: laneX[1], y: startY + i * (boxH + gapY) }; });
    lane2Order.forEach((n, i) => { positions[n.id] = { x: laneX[2], y: startY + i * (boxH + gapY) }; });
    lane3Order.forEach((n, i) => { positions[n.id] = { x: laneX[3], y: startY + i * (boxH + gapY) }; });

    // Subdomain section with IP → ASN columns
    const ipAsnMap = d.ipAsn || {};
    const subIpBoxW = 160, subAsnBoxW = 200;
    const subIpX = laneX[1] + subBoxW + 20;
    const subAsnX = subIpX + subIpBoxW + 20;
    const subStartY = startY + Math.max(lane1Order.length, lane2Order.length, lane3Order.length) * (boxH + gapY) + 40;
    let subRowIdx = 0;
    subNodes.forEach((s) => {
      const ipCount = Math.max(s.ips.length, 1);
      positions[s.id] = { x: laneX[1], y: subStartY + subRowIdx * (subBoxH + subGapY) };
      s.ips.forEach((ip, j) => {
        const rowY = subStartY + (subRowIdx + j) * (subBoxH + subGapY);
        const ipId = 'subip_' + s.id + '_' + ip;
        positions[ipId] = { x: subIpX, y: rowY };
        if (!idSet[ipId]) { idSet[ipId] = true; treeNodes.push({ id: ipId, label: ip, type: 'ip', lane: 2, row: 0 }); }
        addL(s.id, ipId, 'sub');
        // ASN node for this subdomain IP
        const isCf = _isCfIp(ip);
        const asnData = ipAsnMap[ip];
        const asnLabel = isCf ? 'CF PROXY' : (asnData && asnData.asn ? `${asnData.asn} ${(asnData.org || '').slice(0, 25)}` : '');
        if (asnLabel) {
          const asnId = 'subasn_' + s.id + '_' + ip;
          positions[asnId] = { x: subAsnX, y: rowY };
          if (!idSet[asnId]) {
            idSet[asnId] = true;
            treeNodes.push({ id: asnId, label: asnLabel, type: isCf ? 'cf_asn' : 'asn', lane: 3, row: 0 });
          }
          addL(ipId, asnId, isCf ? 'cf' : 'asn');
        }
      });
      subRowIdx += ipCount;
    });
    // Add subdomain nodes to treeNodes
    for (const s of subNodes) {
      if (!treeNodes.find(n => n.id === s.id)) treeNodes.push({ id: s.id, label: s.label, type: s.type, lane: 1, row: 0 });
    }

    const totalH = Math.max(subStartY + subRowIdx * (subBoxH + subGapY) + 60, rect.height || 500);
    const svgW = Math.max(W, subAsnX + subAsnBoxW + 40, laneX[3] + asnBoxW + 40, 920);

    const svg = d3.select(container).append('svg')
      .attr('width', svgW).attr('height', totalH)
      .style('background', _css('--bg'));

    const g = svg.append('g');

    svg.call(d3.zoom().scaleExtent([0.3, 4]).on('zoom', (e) => g.attr('transform', e.transform)));

    // Legend
    const legend = g.append('g').attr('transform', 'translate(60, 20)');
    const legendItems = [
      { label: 'A Record', color: colorMap.a }, { label: 'MX', color: colorMap.mx },
      { label: 'NS', color: colorMap.ns }, { label: 'Subdomain', color: colorMap.subdomain },
      { label: 'IP', color: colorMap.ip }, { label: 'ASN', color: colorMap.asn },
      { label: 'CF Proxy', color: colorMap.cf_ip },
    ];
    legendItems.forEach((item, i) => {
      const lg = legend.append('g').attr('transform', `translate(${i * 100}, 0)`);
      lg.append('rect').attr('width', 10).attr('height', 10).attr('rx', 2).attr('fill', item.color).attr('opacity', 0.8);
      lg.append('text').attr('x', 14).attr('y', 9).text(item.label)
        .attr('fill', _css('--ink-3')).attr('font-family', MONO).attr('font-size', '11px');
    });

    // Subdomain separator
    if (subNodes.length > 0) {
      g.append('line')
        .attr('x1', 40).attr('x2', svgW - 40)
        .attr('y1', subStartY - 20).attr('y2', subStartY - 20)
        .attr('stroke', _css('--line')).attr('stroke-dasharray', '4,4');
      g.append('text').attr('x', 60).attr('y', subStartY - 8)
        .text('Subdomains')
        .attr('fill', _css('--ink-4')).attr('font-family', MONO).attr('font-size', '11px').attr('letter-spacing', '2px');
    }

    // Draw links as curved bezier paths
    for (const link of treeLinks) {
      const sp = positions[link.source];
      const tp = positions[link.target];
      if (!sp || !tp) continue;
      const srcNode = treeNodes.find(n => n.id === link.source);
      const tgtNode = treeNodes.find(n => n.id === link.target);
      const srcIsSub = srcNode?.type === 'subdomain';
      const tgtIsSub = tgtNode?.type === 'subdomain';
      const srcIsSubIp = srcNode && srcNode.id.startsWith('subip_');
      const tgtIsSubAsn = tgtNode && (tgtNode.type === 'cf_asn' || tgtNode.id.startsWith('subasn_'));
      const srcW = srcIsSub ? subBoxW : srcIsSubIp ? subIpBoxW : (boxWidths[srcNode?.lane] || 100);
      const srcH = (srcIsSub || srcIsSubIp || tgtIsSubAsn) ? subBoxH : boxH;
      const tgtH = (tgtIsSub || tgtIsSubAsn) ? subBoxH : boxH;
      const x1 = sp.x + srcW, y1 = sp.y + srcH / 2;
      const x2 = tp.x, y2 = tp.y + tgtH / 2;
      const mx = (x1 + x2) / 2;
      const col = link.type === 'cf' ? colorMap.cf_ip : (colorMap[link.type] || colorMap.a);
      g.append('path')
        .attr('d', `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`)
        .attr('fill', 'none').attr('stroke', col).attr('stroke-opacity', 0.35).attr('stroke-width', 1.5);
    }

    // Draw nodes as boxes
    const tooltip = d3.select(container).append('div').attr('class', 'graph-tooltip').style('display', 'none');

    for (const n of treeNodes) {
      const pos = positions[n.id];
      if (!pos) continue;
      const isSub = n.type === 'subdomain';
      const isSubIp = n.id.startsWith('subip_');
      const isSubAsn = n.id.startsWith('subasn_');
      const isCfAsn = n.type === 'cf_asn';
      const isIpNode = n.type === 'ip' && /^\d+\.\d+\.\d+\.\d+$/.test(n.label);
      const isCf = isIpNode && _isCfIp(n.label);
      const bw = isSub ? subBoxW : isSubIp ? subIpBoxW : isSubAsn ? subAsnBoxW : (boxWidths[n.lane] || 150);
      const bh = (isSub || isSubIp || isSubAsn) ? subBoxH : boxH;
      const col = (isCf || isCfAsn) ? colorMap.cf_ip : (colorMap[n.type] || colorMap.ip);
      const ng = g.append('g').attr('transform', `translate(${pos.x}, ${pos.y})`);

      // Box
      const fillColor = n.type === 'domain' ? 'rgba(124,58,237,0.14)'
        : (isCf || isCfAsn) ? 'rgba(245,158,11,0.08)'
        : isSub ? 'rgba(124,58,237,0.08)' : _css('--bg');
      ng.append('rect')
        .attr('width', bw).attr('height', bh).attr('rx', 3)
        .attr('fill', fillColor)
        .attr('stroke', col).attr('stroke-width', n.type === 'domain' ? 2 : 1)
        .attr('stroke-opacity', n.type === 'domain' ? 0.8 : ((isCf || isCfAsn) ? 0.6 : 0.4));

      // CF badge on IP nodes
      if (isCf) {
        ng.append('rect')
          .attr('x', bw - 24).attr('y', 2).attr('width', 22).attr('height', 12).attr('rx', 2)
          .attr('fill', 'rgba(245,158,11,0.25)').attr('stroke', '#f59e0b').attr('stroke-width', 0.5);
        ng.append('text')
          .attr('x', bw - 13).attr('y', 11).attr('text-anchor', 'middle')
          .attr('fill', '#f59e0b').attr('font-family', MONO).attr('font-size', '9px').attr('font-weight', 'bold')
          .text('CF');
      }

      // Label
      const isAsnType = n.type === 'asn' || isCfAsn;
      const fontSize = n.type === 'domain' ? '11px' : (isSub ? '12px' : (isAsnType ? '10px' : '11px'));
      const charW = isSub ? 6.5 : 7;
      const labelMaxW = isCf ? bw - 28 : bw;
      const maxChars = Math.floor(labelMaxW / charW);
      const label = n.label.length > maxChars ? n.label.slice(0, maxChars - 1) + '…' : n.label;
      const labelX = isCf ? (bw - 26) / 2 : bw / 2;
      ng.append('text')
        .attr('x', labelX).attr('y', bh / 2 + 4)
        .attr('text-anchor', 'middle')
        .attr('fill', isCfAsn ? '#f59e0b' : (isCf ? '#f59e0b' : (n.type === 'domain' ? _css('--ink') : (isSub ? _css('--violet') : (n.type === 'asn' ? _css('--ink-4') : _css('--ink-2'))))))
        .attr('font-family', MONO)
        .attr('font-size', fontSize)
        .text(label);

      // Hover tooltip
      ng.on('mouseover', (e) => {
        let info = n.label;
        if (isCf) {
          info += ' — Cloudflare Proxy - real origin hidden';
        } else if (isCfAsn) {
          info += ' — Cloudflare edge server';
        } else if (n.type === 'ip') {
          const ipAsn = ipAsnMap[n.label];
          if (ipAsn && ipAsn.asn) {
            info += ` — ${ipAsn.asn} (${ipAsn.org || ''})`;
          } else if (asnInfo.asn) {
            info += ` — ${asnInfo.asn} (${asnInfo.org || ''})`;
          }
        }
        tooltip.style('display', 'block').text(info);
      })
      .on('mousemove', (e) => {
        tooltip.style('left', (e.offsetX + 14) + 'px').style('top', (e.offsetY - 10) + 'px');
      })
      .on('mouseout', () => tooltip.style('display', 'none'));
    }
  }
