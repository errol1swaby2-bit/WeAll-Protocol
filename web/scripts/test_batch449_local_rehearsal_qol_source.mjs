import fs from 'node:fs';

function read(path) {
  return fs.readFileSync(path, 'utf8');
}
function assertIncludes(text, needle, label) {
  if (!text.includes(needle)) {
    throw new Error(`${label}: missing ${needle}`);
  }
}

const content = read('src/pages/Content.tsx');
assertIncludes(content, 'getAuthHeaders', 'content scoped auth headers');
assertIncludes(content, 'weall.contentScoped(routeContentId, base, headers)', 'content scoped fallback');
assertIncludes(content, 'weall.content(routeContentId, base)', 'content public fallback');

const messaging = read('src/pages/Messaging.tsx');
assertIncludes(messaging, 'encryptionSetupPending', 'messaging setup pending state');
assertIncludes(messaging, 'auto-publish-messaging-key', 'single auto-publish attempt');
assertIncludes(messaging, 'Waiting for sync', 'messaging sync copy');

const css = read('src/styles.css');
assertIncludes(css, 'Batch 449: keep dense action/detail content inside the center column', 'layout overflow guard marker');
assertIncludes(css, '.appShellContent {\n  overflow-x: clip;', 'center column clipping');
assertIncludes(css, 'repeat(auto-fit, minmax(220px, 1fr))', 'p2p video grid responsive columns');
assertIncludes(css, '@media (max-width: 1320px)', 'mid-width collapse guard');

console.log('batch449 local rehearsal QoL source checks passed');
