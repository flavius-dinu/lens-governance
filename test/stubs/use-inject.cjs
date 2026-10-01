// useInject resolves against the test container the render test installs.
module.exports = { useInject: (injectable) => globalThis.__testDi.inject(injectable), useSyncInject: (injectable, ...params) => globalThis.__testDi.inject(injectable)(...params) };
