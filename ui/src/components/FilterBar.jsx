import React, { useState, useEffect, useRef, useCallback } from 'react'
import { fetchServices, fetchInterfaces } from '../api'
import { getInterfaceName, DIRECTION_ICONS, DIRECTION_COLORS } from '../utils'

const LOG_TYPES = ['firewall', 'dns', 'dhcp', 'wifi', 'system']
const TIME_RANGES = [
  { value: '1h', label: '1h' },
  { value: '6h', label: '6h' },
  { value: '24h', label: '24h' },
  { value: '7d', label: '7d' },
  { value: '30d', label: '30d' },
  { value: '60d', label: '60d' },
]
const ACTIONS = ['allow', 'block', 'redirect']
const DIRECTIONS = ['inbound', 'outbound', 'inter_vlan', 'nat']

export default function FilterBar({ filters, onChange }) {
  const [ipSearch, setIpSearch] = useState(filters.ip || '')
  const [ruleSearch, setRuleSearch] = useState(filters.rule_name || '')
  const [textSearch, setTextSearch] = useState(filters.search || '')
  const [serviceSearch, setServiceSearch] = useState('')
  const [services, setServices] = useState([])
  const [showServiceDropdown, setShowServiceDropdown] = useState(false)
  const [selectedServices, setSelectedServices] = useState(
    filters.service ? filters.service.split(',') : []
  )
  const [interfaceSearch, setInterfaceSearch] = useState('')
  const [interfaces, setInterfaces] = useState([])
  const [showInterfaceDropdown, setShowInterfaceDropdown] = useState(false)
  const [selectedInterfaces, setSelectedInterfaces] = useState(
    filters.interface ? filters.interface.split(',') : []
  )

  // Ref to avoid stale closures in debounce effects
  const filtersRef = useRef(filters)
  useEffect(() => { filtersRef.current = filters }, [filters])

  // Load services for autocomplete
  useEffect(() => {
    fetchServices()
      .then(data => setServices(data.services || []))
      .catch(err => { console.error('Failed to load services:', err); setServices([]) })
  }, [])

  // Load interfaces for filtering
  useEffect(() => {
    fetchInterfaces()
      .then(data => setInterfaces(data.interfaces || []))
      .catch(err => { console.error('Failed to load interfaces:', err); setInterfaces([]) })
  }, [])

  // Debounce text inputs
  useEffect(() => {
    const t = setTimeout(() => onChange({ ...filtersRef.current, ip: ipSearch || null }), 400)
    return () => clearTimeout(t)
  }, [ipSearch]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const t = setTimeout(() => onChange({ ...filtersRef.current, rule_name: ruleSearch || null }), 400)
    return () => clearTimeout(t)
  }, [ruleSearch]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const t = setTimeout(() => onChange({ ...filtersRef.current, search: textSearch || null }), 400)
    return () => clearTimeout(t)
  }, [textSearch]) // eslint-disable-line react-hooks/exhaustive-deps

  const toggleType = (type) => {
    const current = filters.log_type ? filters.log_type.split(',') : LOG_TYPES
    const updated = current.includes(type)
      ? current.filter(t => t !== type)
      : [...current, type]
    onChange({ ...filters, log_type: updated.length === LOG_TYPES.length ? null : updated.join(',') })
  }

  const activeTypes = filters.log_type ? filters.log_type.split(',') : LOG_TYPES
  const activeActions = filters.rule_action ? filters.rule_action.split(',') : ACTIONS
  const activeDirections = filters.direction ? filters.direction.split(',') : DIRECTIONS

  const toggleAction = (action) => {
    const current = filters.rule_action ? filters.rule_action.split(',') : ACTIONS
    const updated = current.includes(action)
      ? current.filter(a => a !== action)
      : [...current, action]
    onChange({ ...filters, rule_action: updated.length === ACTIONS.length ? null : updated.join(',') })
  }

  const toggleDirection = (dir) => {
    const current = filters.direction ? filters.direction.split(',') : DIRECTIONS
    const updated = current.includes(dir)
      ? current.filter(d => d !== dir)
      : [...current, dir]
    onChange({ ...filters, direction: updated.length === DIRECTIONS.length ? null : updated.join(',') })
  }

  const typeColors = {
    firewall: 'bg-blue-500',
    dns: 'bg-violet-500',
    dhcp: 'bg-cyan-500',
    wifi: 'bg-amber-500',
    system: 'bg-gray-500',
  }

  return (
    <div className="space-y-3">
      {/* Row 1: Log types + time range */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex items-center gap-1.5">
          {LOG_TYPES.map(type => (
            <button
              key={type}
              onClick={() => toggleType(type)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
                activeTypes.includes(type)
                  ? `${typeColors[type]} text-white`
                  : 'bg-gray-800 text-gray-400 hover:text-gray-300'
              }`}
            >
              {type}
            </button>
          ))}
        </div>

        <div className="h-5 w-px bg-gray-700" />

        <div className="flex items-center gap-1">
          {ACTIONS.map(action => (
            <button
              key={action}
              onClick={() => toggleAction(action)}
              className={`px-2 py-1 rounded text-xs font-medium transition-all ${
                activeActions.includes(action)
                  ? action === 'block' ? 'bg-red-500/30 text-red-400' : action === 'allow' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-yellow-500/20 text-yellow-400'
                  : 'bg-gray-800 text-gray-400 hover:text-gray-300'
              }`}
            >
              {action}
            </button>
          ))}
        </div>

        <div className="h-5 w-px bg-gray-700" />

        <div className="flex items-center gap-1">
          {DIRECTIONS.map(dir => (
            <button
              key={dir}
              onClick={() => toggleDirection(dir)}
              className={`px-2 py-1 rounded text-xs font-medium transition-all ${
                activeDirections.includes(dir)
                  ? 'bg-gray-700 text-white'
                  : 'text-gray-500 hover:text-gray-400'
              }`}
            >
              <span className={activeDirections.includes(dir) ? DIRECTION_COLORS[dir] : ''}>{DIRECTION_ICONS[dir]}</span> {dir === 'inter_vlan' ? 'vlan' : dir}
            </button>
          ))}
        </div>

        <div className="h-5 w-px bg-gray-700" />

        <div className="flex items-center gap-1">
          {TIME_RANGES.map(tr => (
            <button
              key={tr.value}
              onClick={() => onChange({ ...filters, time_range: tr.value })}
              className={`px-2 py-1 rounded text-xs font-medium transition-all ${
                filters.time_range === tr.value
                  ? 'bg-gray-700 text-white'
                  : 'text-gray-400 hover:text-gray-300'
              }`}
            >
              {tr.label}
            </button>
          ))}
        </div>
      </div>

      {/* Row 2: Text searches */}
      <div className="flex items-center gap-3">
        <div className="relative">
          <input
            type="text"
            placeholder="IP address..."
            value={ipSearch}
            onChange={e => setIpSearch(e.target.value)}
            className="bg-gray-800/50 border border-gray-700 rounded px-3 py-1.5 text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-gray-500 w-40"
          />
          {ipSearch && (
            <button onClick={() => setIpSearch('')} className="absolute right-2 top-1.5 text-gray-400 hover:text-gray-200 text-xs">✕</button>
          )}
        </div>
        <div className="relative">
          <input
            type="text"
            placeholder="Rule name..."
            value={ruleSearch}
            onChange={e => setRuleSearch(e.target.value)}
            className="bg-gray-800/50 border border-gray-700 rounded px-3 py-1.5 text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-gray-500 w-40"
          />
          {ruleSearch && (
            <button onClick={() => setRuleSearch('')} className="absolute right-2 top-1.5 text-gray-400 hover:text-gray-200 text-xs">✕</button>
          )}
        </div>
        <div className="relative">
          <input
            type="text"
            placeholder={selectedServices.length > 0 ? `${selectedServices.length} service(s)` : "Service..."}
            value={serviceSearch}
            onChange={e => {
              setServiceSearch(e.target.value)
              setShowServiceDropdown(true)
            }}
            onFocus={() => setShowServiceDropdown(true)}
            onBlur={() => setTimeout(() => setShowServiceDropdown(false), 200)}
            className="bg-gray-800/50 border border-gray-700 rounded px-3 py-1.5 text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-gray-500 w-40"
          />
          {selectedServices.length > 0 && (
            <button
              onClick={() => {
                setSelectedServices([])
                onChange({ ...filters, service: null })
              }}
              className="absolute right-2 top-1.5 text-gray-400 hover:text-gray-200 text-xs"
            >✕</button>
          )}
          {showServiceDropdown && (
            <div className="absolute top-full left-0 mt-1 w-56 bg-gray-800 border border-gray-700 rounded shadow-lg max-h-60 overflow-y-auto z-10">
              {services
                .filter(s => s.toLowerCase().includes(serviceSearch.toLowerCase()))
                .slice(0, 50)
                .map(service => (
                  <div
                    key={service}
                    onClick={() => {
                      const updated = selectedServices.includes(service)
                        ? selectedServices.filter(s => s !== service)
                        : [...selectedServices, service]
                      setSelectedServices(updated)
                      onChange({ ...filters, service: updated.length ? updated.join(',') : null })
                      setServiceSearch('')
                    }}
                    className={`px-3 py-2 text-xs cursor-pointer transition-colors ${
                      selectedServices.includes(service)
                        ? 'bg-blue-500/20 text-blue-400'
                        : 'text-gray-300 hover:bg-gray-700'
                    }`}
                  >
                    {service}
                  </div>
                ))}
              {services.filter(s => s.toLowerCase().includes(serviceSearch.toLowerCase())).length === 0 && (
                <div className="px-3 py-2 text-xs text-gray-400">No matching services</div>
              )}
            </div>
          )}
        </div>
        <div className="relative">
          <input
            type="text"
            placeholder={selectedInterfaces.length > 0 ? `${selectedInterfaces.length} interface(s)` : "Interface..."}
            value={interfaceSearch}
            onChange={e => {
              setInterfaceSearch(e.target.value)
              setShowInterfaceDropdown(true)
            }}
            onFocus={() => setShowInterfaceDropdown(true)}
            onBlur={() => setTimeout(() => setShowInterfaceDropdown(false), 200)}
            className="bg-gray-800/50 border border-gray-700 rounded px-3 py-1.5 text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-gray-500 w-40"
          />
          {selectedInterfaces.length > 0 && (
            <button
              onClick={() => {
                setSelectedInterfaces([])
                onChange({ ...filters, interface: null })
              }}
              className="absolute right-2 top-1.5 text-gray-400 hover:text-gray-200 text-xs"
            >✕</button>
          )}
          {showInterfaceDropdown && (
            <div className="absolute top-full left-0 mt-1 w-56 bg-gray-800 border border-gray-700 rounded shadow-lg max-h-60 overflow-y-auto z-10">
              {interfaces
                .filter(iface =>
                  iface.name.toLowerCase().includes(interfaceSearch.toLowerCase()) ||
                  iface.label.toLowerCase().includes(interfaceSearch.toLowerCase())
                )
                .slice(0, 50)
                .map(iface => (
                  <div
                    key={iface.name}
                    onClick={() => {
                      const updated = selectedInterfaces.includes(iface.name)
                        ? selectedInterfaces.filter(i => i !== iface.name)
                        : [...selectedInterfaces, iface.name]
                      setSelectedInterfaces(updated)
                      onChange({ ...filters, interface: updated.length ? updated.join(',') : null })
                      setInterfaceSearch('')
                    }}
                    className={`px-3 py-2 text-xs cursor-pointer transition-colors ${
                      selectedInterfaces.includes(iface.name)
                        ? 'bg-blue-500/20 text-blue-400'
                        : 'text-gray-300 hover:bg-gray-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono">{iface.name}</span>
                      {iface.label !== iface.name && (
                        <span className="text-gray-400 ml-2">{iface.label}</span>
                      )}
                    </div>
                  </div>
                ))}
              {interfaces.filter(iface =>
                iface.name.toLowerCase().includes(interfaceSearch.toLowerCase()) ||
                iface.label.toLowerCase().includes(interfaceSearch.toLowerCase())
              ).length === 0 && (
                <div className="px-3 py-2 text-xs text-gray-400">No matching interfaces</div>
              )}
            </div>
          )}
        </div>
        <div className="relative flex-1 max-w-xs">
          <input
            type="text"
            placeholder="Search raw log..."
            value={textSearch}
            onChange={e => setTextSearch(e.target.value)}
            className="w-full bg-gray-800/50 border border-gray-700 rounded px-3 py-1.5 text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-gray-500"
          />
          {textSearch && (
            <button onClick={() => setTextSearch('')} className="absolute right-2 top-1.5 text-gray-400 hover:text-gray-200 text-xs">✕</button>
          )}
        </div>
        <button
          onClick={() => {
            setIpSearch('')
            setRuleSearch('')
            setTextSearch('')
            setServiceSearch('')
            setSelectedServices([])
            setInterfaceSearch('')
            setSelectedInterfaces([])
            onChange({ time_range: '24h', page: 1, per_page: 50 })
          }}
          className="text-xs text-gray-400 hover:text-gray-200 transition-colors"
        >
          Reset
        </button>
      </div>
    </div>
  )
}
