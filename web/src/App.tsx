import { Route, Routes } from 'react-router-dom';
import Live from './screens/Live';
import Incidents from './screens/Incidents';
import Summary from './screens/Summary';
import About from './screens/About';
import NotFound from './screens/NotFound';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Live />} />
      <Route path="/incidents" element={<Incidents />} />
      <Route path="/summary" element={<Summary />} />
      <Route path="/about" element={<About />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
