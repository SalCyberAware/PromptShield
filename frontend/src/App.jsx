import Header from './components/Header.jsx'
import ScanInput from './components/ScanInput.jsx'
import HonestyNote from './components/HonestyNote.jsx'
import Footer from './components/Footer.jsx'

export default function App() {
  return (
    <div className="ps-app">
      <Header />

      <main className="ps-main">
        <div className="ps-container">
          <section className="ps-hero">
            <h1 className="ps-title">Is your system prompt secure?</h1>
            <p className="ps-subtitle">
              Paste it in. We attack it 13 ways: prompt injection, jailbreaks,
              system-prompt leaks. Then we show you exactly what breaks.
            </p>
          </section>

          <ScanInput />
          <HonestyNote />
        </div>
      </main>

      <Footer />
    </div>
  )
}
