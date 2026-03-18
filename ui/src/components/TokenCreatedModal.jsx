import { createPortal } from 'react-dom'
import { useEffect, useId, useRef } from 'react'
import CopyButton from './CopyButton'

export default function TokenCreatedModal({ token, title = 'Token Created', onClose }) {
  const titleId = useId()
  const dialogRef = useRef(null)

  useEffect(() => {
    if (token) dialogRef.current?.focus()
  }, [token])

  if (!token) return null
  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="bg-gray-950 border border-gray-700 rounded-lg shadow-xl max-w-lg w-full mx-4 outline-none"
        onClick={e => e.stopPropagation()}
        onKeyDown={e => e.key === 'Escape' && onClose()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700">
          <span id={titleId} className="text-sm font-semibold text-gray-200">{title}</span>
          <button onClick={onClose} aria-label="Close" className="text-gray-400 hover:text-gray-200 text-lg leading-none">
            &times;
          </button>
        </div>
        <div className="px-4 py-4 space-y-3">
          <p className="text-sm text-gray-400">
            This token is shown only once. Copy it now and store it securely.
          </p>
          <div className="flex items-center gap-2">
            <input
              type="text"
              readOnly
              value={token}
              aria-label="Generated token"
              className="flex-1 px-3 py-2 rounded bg-gray-900 border border-gray-700 text-sm text-gray-200 font-mono"
            />
            <CopyButton text={token} />
          </div>
        </div>
        <div className="px-4 py-3 border-t border-gray-700 flex justify-end">
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded text-sm font-medium bg-teal-600 hover:bg-teal-500 text-white transition-colors"
          >
            Done
          </button>
        </div>
      </div>
    </div>,
    document.body
  )
}
