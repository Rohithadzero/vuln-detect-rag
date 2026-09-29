import React from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'
import { Button, Card } from './ui'

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
        <div className="min-h-screen flex items-center justify-center bg-canvas p-6">
          <Card className="p-8 max-w-md w-full text-center">
            <AlertTriangle className="w-8 h-8 text-crit mx-auto mb-3" aria-hidden="true" />
            <h1 className="text-lg font-semibold mb-1">Something went wrong</h1>
            <p className="text-[13px] text-ink-muted mb-5 break-words">
              {this.state.error?.message || 'An unexpected error occurred.'}
            </p>
            <Button
              variant="primary"
              icon={RefreshCw}
              onClick={() => {
                this.setState({ hasError: false, error: null })
                window.location.href = '/'
              }}
            >
              Reload app
            </Button>
          </Card>
        </div>
      )
    }

    return this.props.children
  }
}
