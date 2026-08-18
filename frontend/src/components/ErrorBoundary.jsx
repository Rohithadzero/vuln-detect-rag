import React from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.error('ErrorBoundary caught:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center h-full bg-stone-100 p-8">
          <div className="bg-white border-3 border-black p-8 max-w-md text-center shadow-[8px_8px_0px_0px_#000]">
            <AlertTriangle className="w-12 h-12 text-neo-red mx-auto mb-4" />
            <h2 className="text-xl font-black mb-2 uppercase">Something went wrong</h2>
            <p className="text-sm font-bold text-gray-500 mb-4">
              {this.state.error?.message || 'An unexpected error occurred.'}
            </p>
            <button
              onClick={() => {
                this.setState({ hasError: false, error: null })
                window.location.href = '/'
              }}
              className="inline-flex items-center gap-2 px-6 py-3 bg-neo-yellow border-3 border-black nb-btn text-sm"
            >
              <RefreshCw className="w-4 h-4" /> Reload App
            </button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
