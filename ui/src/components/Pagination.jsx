import React, { useState } from 'react'
import { formatNumber } from '../utils'

function renderMarkdown(md) {
  if (!md) return ''
  const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
  return esc(md)
    .replace(/^### (.+)$/gm, '<h3 class="text-xs font-semibold text-gray-200 mt-3 mb-1">$1</h3>')
    .replace(/^## (.+)$/gm, '<h2 class="text-sm font-semibold text-gray-100 mt-4 mb-1.5">$1</h2>')
    .replace(/\*\*(.+?)\*\*/g, '<strong class="text-gray-200">$1</strong>')
    .replace(/`([^`]+)`/g, '<code class="px-1 py-0.5 bg-gray-800 rounded text-[10px] text-gray-300">$1</code>')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, text, url) => {
      const href = /^(https?:\/\/|mailto:|\/|#)/i.test(url.trim()) ? url : '#'
      return `<a href="${href}" target="_blank" rel="noopener noreferrer" class="text-blue-400 hover:text-blue-300">${text}</a>`
    })
    .replace(/^- (.+)$/gm, '<li class="ml-3 pl-1">$1</li>')
    .replace(/((?:<li[^>]*>.*<\/li>\n?)+)/g, '<ul class="list-disc space-y-0.5 my-1">$1</ul>')
    .replace(/<\/li>\n<li/g, '</li><li')
    .replace(/\n{2,}/g, '<div class="h-2"></div>')
    .replace(/\n/g, '<br/>')
}

function isNewerVersion(latest, current) {
  if (!latest || !current) return false
  const parse = v => v.replace(/^v/, '').split('.').map(Number)
  const [lMaj, lMin, lPatch] = parse(latest)
  const [cMaj, cMin, cPatch] = parse(current)
  if (lMaj !== cMaj) return lMaj > cMaj
  if (lMin !== cMin) return lMin > cMin
  return lPatch > cPatch
}

export default function Pagination({ page, pages, total, perPage, onChange, version, latestRelease }) {
  const start = (page - 1) * perPage + 1
  const end = Math.min(page * perPage, total)
  const outdated = latestRelease && isNewerVersion(latestRelease.tag, version)
  const [showNotes, setShowNotes] = useState(false)

  // Close release notes modal on Escape
  React.useEffect(() => {
    if (!showNotes) return
    const onKey = e => { if (e.key === 'Escape') setShowNotes(false) }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [showNotes])

  return (
    <>
      <div className="flex items-center justify-between px-3 py-2 border-t border-gray-800">
        <span className="text-[11px] text-gray-400">
          {total > 0 ? `${formatNumber(start)}–${formatNumber(end)} of ${formatNumber(total)}` : 'No results'}
        </span>
        {version && (
          <div className="flex items-center gap-1.5">
            <span className={`text-[10px] ${outdated ? 'text-amber-400' : 'text-white'}`}>v{version}</span>
            {outdated ? (
              <a
                href={latestRelease.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-[10px] text-amber-400 hover:text-amber-300 transition-colors"
                title={`Update available, check it out: ${latestRelease.tag}`}
              >
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-3.5 h-3.5">
                  <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                </svg>
                Update available
              </a>
            ) : latestRelease?.body && (
              <button
                onClick={() => setShowNotes(true)}
                className="text-[10px] text-gray-400 hover:text-gray-200 transition-colors"
              >
                - Release Notes
              </button>
            )}
          </div>
        )}
        <div className="flex items-center gap-1">
          <button
            disabled={page <= 1}
            onClick={() => onChange(1)}
            className="px-2 py-1 text-xs text-gray-400 hover:text-gray-200 disabled:text-gray-700 disabled:cursor-not-allowed"
          >
            ««
          </button>
          <button
            disabled={page <= 1}
            onClick={() => onChange(page - 1)}
            className="px-2 py-1 text-xs text-gray-400 hover:text-gray-200 disabled:text-gray-700 disabled:cursor-not-allowed"
          >
            «
          </button>
          <span className="px-3 py-1 text-xs text-gray-300">
            {page} / {pages || 1}
          </span>
          <button
            disabled={page >= pages}
            onClick={() => onChange(page + 1)}
            className="px-2 py-1 text-xs text-gray-400 hover:text-gray-200 disabled:text-gray-700 disabled:cursor-not-allowed"
          >
            »
          </button>
          <button
            disabled={page >= pages}
            onClick={() => onChange(pages)}
            className="px-2 py-1 text-xs text-gray-400 hover:text-gray-200 disabled:text-gray-700 disabled:cursor-not-allowed"
          >
            »»
          </button>
        </div>
      </div>

      {/* Release Notes Modal */}
      {showNotes && latestRelease && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={() => setShowNotes(false)}>
          <div role="dialog" aria-modal="true" aria-labelledby="release-notes-title" className="bg-gray-900 border border-gray-700 rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[70vh] flex flex-col" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700">
              <span id="release-notes-title" className="text-sm font-semibold text-gray-200">Release Notes — {latestRelease.tag}</span>
              <button onClick={() => setShowNotes(false)} className="text-gray-400 hover:text-gray-200 text-lg leading-none">&times;</button>
            </div>
            <div className="px-4 py-3 overflow-y-auto text-xs text-gray-300 leading-relaxed" dangerouslySetInnerHTML={{ __html: renderMarkdown(latestRelease.body) }} />
            <div className="px-4 py-3 border-t border-gray-700 flex justify-end">
              <a
                href={latestRelease.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
              >
                View on GitHub
              </a>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
