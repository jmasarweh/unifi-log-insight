import React, { useState, useEffect } from 'react'
import { fetchAllReleases } from '../api'

export function renderMarkdown(md) {
  if (!md) return ''
  const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
  return esc(md)
    .replace(/^### (.+)$/gm, '<h3 class="text-xs font-semibold text-gray-200 mt-2 mb-0.5">$1</h3>')
    .replace(/^## (.+)$/gm, '<h2 class="text-sm font-semibold text-gray-100 mt-3 mb-1">$1</h2>')
    .replace(/\*\*(.+?)\*\*/g, '<strong class="text-gray-200">$1</strong>')
    .replace(/`([^`]+)`/g, '<code class="px-1 py-0.5 bg-gray-800 rounded text-[10px] text-gray-300">$1</code>')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, text, url) => {
      const href = /^(https?:\/\/|mailto:|\/|#)/i.test(url.trim()) ? url : '#'
      return `<a href="${href}" target="_blank" rel="noopener noreferrer" class="text-blue-400 hover:text-blue-300">${text}</a>`
    })
    .replace(/^- (.+)$/gm, '<li class="ml-3 pl-1">$1</li>')
    .replace(/((?:<li[^>]*>.*<\/li>\n?)+)/g, '<ul class="list-disc space-y-0.5 my-1">$1</ul>')
    .replace(/<\/li>\n<li/g, '</li><li')
    .replace(/\n{2,}/g, '<div class="h-1"></div>')
    .replace(/\n(?=<(?:h[23]|ul|\/ul|div))/g, '')
    .replace(/(<\/(?:h[23]|ul|div)>)\n/g, '$1')
    .replace(/\n/g, '<br/>')
}

export function isNewerVersion(latest, current) {
  if (!latest || !current) return false
  const parse = v => v.replace(/^v/, '').split('.').map(Number)
  const [lMaj, lMin, lPatch] = parse(latest)
  const [cMaj, cMin, cPatch] = parse(current)
  if (lMaj !== cMaj) return lMaj > cMaj
  if (lMin !== cMin) return lMin > cMin
  return lPatch > cPatch
}

export default function ReleaseNotesModal({ latestRelease, onClose, currentVersion }) {
  const [allReleases, setAllReleases] = useState(null)
  const [loadingReleases, setLoadingReleases] = useState(false)
  const [selectedRelease, setSelectedRelease] = useState(null)
  const displayedRelease = selectedRelease || latestRelease

  useEffect(() => {
    const onKey = e => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  useEffect(() => {
    if (allReleases) return
    setLoadingReleases(true)
    fetchAllReleases()
      .then(releases => { if (releases) setAllReleases(releases) })
      .catch(() => {})
      .finally(() => setLoadingReleases(false))
  }, [])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div role="dialog" aria-modal="true" aria-labelledby="release-notes-title" className="bg-gray-950 border border-gray-700 rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[70vh] flex flex-col" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700">
          <span id="release-notes-title" className="text-sm font-semibold text-gray-200">Release Notes — {displayedRelease.tag}</span>
          <div className="flex items-center gap-3">
            {loadingReleases ? (
              <span className="text-[10px] text-gray-500">Loading versions...</span>
            ) : allReleases && allReleases.length > 1 && (
              <div className="flex items-center gap-1.5">
                <label htmlFor="previous-releases-select" className="text-xs text-gray-500">Previous Releases:</label>
                <select
                  id="previous-releases-select"
                  value={displayedRelease.tag}
                  onChange={e => {
                    const rel = allReleases.find(r => r.tag === e.target.value)
                    if (rel) setSelectedRelease(rel.tag === allReleases[0].tag ? null : rel)
                  }}
                  className="px-2 py-1 bg-gray-900 border border-gray-600 rounded text-[11px] text-gray-300 focus:border-teal-500 focus:outline-none"
                >
                  {allReleases.map(r => (
                    <option key={r.tag} value={r.tag}>
                      {r.tag}{r.tag === allReleases[0].tag ? ' (latest)' : ''}
                    </option>
                  ))}
                </select>
              </div>
            )}
            <button onClick={onClose} className="text-gray-400 hover:text-gray-200 text-lg leading-none">&times;</button>
          </div>
        </div>
        {currentVersion && isNewerVersion(displayedRelease.tag, currentVersion) && (
          <div className="mx-4 mt-3 flex items-start gap-2 bg-amber-500/10 border border-amber-500/30 rounded px-3 py-2">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5">
              <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
            </svg>
            <p className="text-[11px] text-amber-400/90">
              You are running <strong>v{currentVersion}</strong>. These are the release notes for <strong>{displayedRelease.tag}</strong>.
            </p>
          </div>
        )}
        <div className="px-4 py-3 overflow-y-auto text-xs text-gray-300 leading-normal" dangerouslySetInnerHTML={{ __html: renderMarkdown(displayedRelease.body) }} />
        <div className="px-4 py-3 border-t border-gray-700 flex justify-end">
          <a
            href={displayedRelease.url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
          >
            View on GitHub
          </a>
        </div>
      </div>
    </div>
  )
}
