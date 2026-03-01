import { useState, useEffect, useRef } from 'react'
import { DayPicker } from 'react-day-picker'
import 'react-day-picker/style.css'

export default function DateRangePicker({ isActive, timeFrom, timeTo, onApply, onClear, maxFilterDays }) {
  const [open, setOpen] = useState(false)
  const [range, setRange] = useState({ from: undefined, to: undefined })
  const [startTime, setStartTime] = useState('00:00')
  const [endTime, setEndTime] = useState('23:59')
  const ref = useRef(null)

  // Close on outside click
  useEffect(() => {
    if (!open) return
    const handleClickOutside = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    const handleEscape = (e) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', handleClickOutside)
    document.addEventListener('keydown', handleEscape)
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
      document.removeEventListener('keydown', handleEscape)
    }
  }, [open])

  // Snapshot props into local state only when popover opens.
  // Intentionally depends on [open] alone — including isActive/timeFrom/timeTo
  // would reset the user's in-progress selection on every parent re-render.
  useEffect(() => {
    if (!open) return
    if (isActive && timeFrom) {
      const from = new Date(timeFrom)
      const to = timeTo ? new Date(timeTo) : new Date()
      if (!isNaN(from.getTime()) && !isNaN(to.getTime())) {
        setRange({ from, to })
      } else {
        setRange({ from: undefined, to: undefined })
      }
    } else {
      setRange({ from: undefined, to: undefined })
    }
    // Always reset times to full-day defaults
    setStartTime('00:00')
    setEndTime('23:59')
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps

  // Compute earliest allowed date based on maxFilterDays
  const earliestDate = maxFilterDays
    ? new Date(Date.now() - maxFilterDays * 86400000)
    : undefined

  const combineDateAndTime = (date, time) => {
    const [h = 0, m = 0] = (time || '').split(':').map(Number)
    const d = new Date(date)
    d.setHours(h || 0, m || 0, 0, 0)
    return d
  }

  const handleApply = () => {
    if (!range.from) return
    const effectiveTo = range.to || range.from
    let from = combineDateAndTime(range.from, startTime)
    const to = combineDateAndTime(effectiveTo, endTime)
    // Clamp from to earliestDate if maxFilterDays is set
    if (earliestDate && from < earliestDate) from = earliestDate
    // Swap if inverted (e.g. same day with start time after end time)
    const [final_from, final_to] = from > to ? [to, from] : [from, to]
    onApply({ time_from: final_from.toISOString(), time_to: final_to.toISOString() })
    setOpen(false)
  }

  const handleClear = () => {
    onClear()
    setOpen(false)
  }

  // Format the active range label
  const formatLabel = () => {
    if (!isActive || !timeFrom) return null
    const from = new Date(timeFrom)
    const to = timeTo ? new Date(timeTo) : new Date()
    if (isNaN(from.getTime()) || isNaN(to.getTime())) return null
    const fmt = (d) => d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' })
    const fmtTime = (d) => d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
    return `${fmt(from)} ${fmtTime(from)} → ${fmt(to)} ${fmtTime(to)}`
  }

  const label = formatLabel()

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(!open)}
        className={`px-2 py-1 rounded text-xs font-medium transition-all ${
          isActive
            ? 'bg-gray-700 text-white'
            : 'text-gray-400 hover:text-gray-300'
        }`}
      >
        Custom
      </button>
      {isActive && label && (
        <span className="ml-1 text-[10px] date-range-label">{label}</span>
      )}
      {open && (
        <div role="dialog" aria-modal="true" aria-label="Select custom date range" className="absolute top-full left-0 mt-1 z-30 bg-gray-950 border border-gray-700 rounded-lg shadow-lg p-3">
          <DayPicker
            mode="range"
            selected={range}
            onSelect={(val) => setRange(val || { from: undefined, to: undefined })}
            disabled={[{ after: new Date() }, ...(earliestDate ? [{ before: earliestDate }] : [])]}
            endMonth={new Date()}
            startMonth={earliestDate}
            classNames={{ root: 'rdp-dark' }}
          />
          <div className="flex items-center gap-2 mt-2 pt-2 border-t border-gray-800">
            <label htmlFor="drp-start-time" className="text-[10px] text-gray-500">From</label>
            <input
              id="drp-start-time"
              type="time"
              value={startTime}
              onChange={(e) => setStartTime(e.target.value)}
              className="bg-gray-800/50 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 focus:outline-none focus:border-gray-500"
            />
            <label htmlFor="drp-end-time" className="text-[10px] text-gray-500">To</label>
            <input
              id="drp-end-time"
              type="time"
              value={endTime}
              onChange={(e) => setEndTime(e.target.value)}
              className="bg-gray-800/50 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 focus:outline-none focus:border-gray-500"
            />
          </div>
          <div className="flex gap-2 mt-2">
            <button
              onClick={handleApply}
              disabled={!range.from}
              className="flex-1 px-3 py-1.5 rounded text-xs font-medium bg-teal-600 text-white hover:bg-teal-500 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Apply
            </button>
            <button
              onClick={handleClear}
              className="px-3 py-1.5 rounded text-xs font-medium text-gray-400 hover:text-gray-200 border border-gray-700 hover:border-gray-600 transition-colors"
            >
              Clear
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
