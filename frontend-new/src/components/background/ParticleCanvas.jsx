import { useEffect, useRef } from 'react';
import './ParticleCanvas.css';

/*
 * Particle canvas — ported from the Malware AI Analyzer reference HTML.
 * Key behaviors:
 *   - Particles bounce off viewport edges (not wrap)
 *   - ~10% are crimson-red; rest are blue-grey
 *   - 3 slow-drifting crimson radial glow blobs
 *   - Connection lines: blue or red depending on nearest particle
 *   - shadowBlur glow on each particle dot
 */

const MAX_DIST    = 132;
const MAX_DIST_SQ = MAX_DIST * MAX_DIST;
const SPEED       = 0.22;
const RED_RATIO   = 0.10;

function densityDivisor() {
  const w = window.innerWidth;
  if (w < 768) return 14000;
  if (w < 1200) return 10000;
  return 8000;
}

function buildParticles(w, h) {
  const N = Math.min(120, Math.max(28, Math.floor((w * h) / densityDivisor())));
  return Array.from({ length: N }, () => ({
    x:   Math.random() * w,
    y:   Math.random() * h,
    vx:  (Math.random() - 0.5) * SPEED,
    vy:  (Math.random() - 0.5) * SPEED,
    r:   Math.random() * 1.5 + 0.6,
    red: Math.random() < RED_RATIO,
  }));
}

function buildBlobs(w, h) {
  return Array.from({ length: 3 }, () => ({
    x:  Math.random() * w,
    y:  Math.random() * h,
    vx: (Math.random() - 0.5) * 0.12,
    vy: (Math.random() - 0.5) * 0.12,
    r:  Math.random() * 180 + 220,
  }));
}

export function ParticleCanvas() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (mq.matches) return;

    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx    = canvas.getContext('2d');
    const dpr    = Math.min(window.devicePixelRatio || 1, 2);
    let W = 0, H = 0;
    let particles = [], blobs = [];
    let rafId;

    function resize() {
      W = window.innerWidth;
      H = window.innerHeight;
      canvas.width  = W * dpr;
      canvas.height = H * dpr;
      canvas.style.width  = W + 'px';
      canvas.style.height = H + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      particles = buildParticles(W, H);
      blobs     = buildBlobs(W, H);
    }

    function loop() {
      ctx.clearRect(0, 0, W, H);

      /* ── Crimson glow blobs (radial gradient drifters) ───────────── */
      blobs.forEach(b => {
        b.x += b.vx; b.y += b.vy;
        if (b.x < -320 || b.x > W + 320) b.vx *= -1;
        if (b.y < -320 || b.y > H + 320) b.vy *= -1;
        const g = ctx.createRadialGradient(b.x, b.y, 0, b.x, b.y, b.r);
        g.addColorStop(0, 'rgba(225,29,42,0.05)');
        g.addColorStop(1, 'rgba(225,29,42,0)');
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(b.x, b.y, b.r, 0, Math.PI * 2);
        ctx.fill();
      });

      /* ── Connection lines ────────────────────────────────────────── */
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const a = particles[i], b = particles[j];
          const dx = a.x - b.x, dy = a.y - b.y;
          const d2 = dx * dx + dy * dy;
          if (d2 >= MAX_DIST_SQ) continue;
          const o = (1 - Math.sqrt(d2) / MAX_DIST) * 0.16;
          ctx.strokeStyle = (a.red || b.red)
            ? `rgba(225,80,92,${o})`
            : `rgba(86,124,196,${o})`;
          ctx.lineWidth = 0.6;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }

      /* ── Particles ───────────────────────────────────────────────── */
      particles.forEach(p => {
        p.x += p.vx; p.y += p.vy;
        if (p.x <= 0 || p.x >= W) p.vx *= -1;
        if (p.y <= 0 || p.y >= H) p.vy *= -1;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        if (p.red) {
          ctx.fillStyle  = 'rgba(232,72,82,0.95)';
          ctx.shadowColor = 'rgba(225,29,42,0.9)';
          ctx.shadowBlur  = 8;
        } else {
          ctx.fillStyle  = 'rgba(150,182,236,0.7)';
          ctx.shadowColor = 'rgba(86,124,210,0.55)';
          ctx.shadowBlur  = 5;
        }
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      rafId = requestAnimationFrame(loop);
    }

    resize();
    loop();
    window.addEventListener('resize', resize);

    return () => {
      cancelAnimationFrame(rafId);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return (
    <div className="bg-layer" aria-hidden="true">
      <canvas ref={canvasRef} className="bg-canvas" />
    </div>
  );
}
