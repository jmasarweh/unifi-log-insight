export default function FlowViewSkeleton() {
  return (
    <div className="p-4 space-y-4 overflow-auto max-h-full animate-pulse">
      <div className="flex gap-1">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-7 w-10 bg-gray-800 rounded" />
        ))}
      </div>
      <div className="border border-gray-800 rounded-lg p-4 h-72" />
      <div className="border border-gray-800 rounded-lg p-4 h-64" />
    </div>
  )
}
