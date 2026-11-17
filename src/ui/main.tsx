/**
 * Browser bootstrap: mount <App /> and paint the theme band above a sticky
 * header on phones with a notch.
 */

import { render } from 'preact';
import { App } from './App.tsx';
import './styles.css';

const root = document.getElementById('root');
if (!root) throw new Error('missing #root');
render(<App />, root);
