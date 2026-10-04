// Self-hosted faces only: the strict CSP forbids external hosts. Vite fingerprints the woff2 files
// into /assets and `build.assetsInlineLimit: 0` keeps them out of data: URIs. The latin subsets
// cover Latin letters and digits; CJK text is drawn with the system fonts in the font stack.
import "@fontsource/ibm-plex-sans/latin-400.css";
import "@fontsource/ibm-plex-sans/latin-500.css";
import "@fontsource/ibm-plex-sans/latin-600.css";
import "@fontsource/ibm-plex-sans/latin-700.css";
import "@fontsource/jetbrains-mono/latin-400.css";
import "@fontsource/jetbrains-mono/latin-500.css";
