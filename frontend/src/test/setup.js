// Vitest setup, loaded once per test file.
//
// Adds the jest-dom matchers (toBeInTheDocument, toBeDisabled, ...) and unmounts
// anything React Testing Library rendered. RTL only auto-cleans when vitest
// globals are on, and they are off here, so the hook is registered by hand.
import '@testing-library/jest-dom/vitest'
import { afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'

afterEach(cleanup)
