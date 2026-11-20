import { Link } from 'react-router-dom';
import Page from '../components/Page';

export default function NotFound() {
  return <Page title="Page not found"><Link to="/">Return to Live</Link></Page>;
}
