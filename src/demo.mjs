import { audit } from './audit.mjs';
import { buildDemoTree, removeDemoTree } from './demo-tree.mjs';

export function runDemo({ version, scheduleFile, lifetimes }) {
  const root = buildDemoTree();
  try {
    return audit({ root, scheduleFile, lifetimes, version });
  } finally {
    removeDemoTree(root);
  }
}
