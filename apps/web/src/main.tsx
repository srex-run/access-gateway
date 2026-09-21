import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { RouterProvider } from 'react-router-dom'
import '@arco-design/web-react/dist/css/arco.css'
import { Providers } from './app/providers'
import { router } from './app/router'
import './app/styles.css'

const container = document.getElementById('root')
if (!container) throw new Error('Application root is missing')
createRoot(container).render(<StrictMode><Providers><RouterProvider router={router} /></Providers></StrictMode>)
