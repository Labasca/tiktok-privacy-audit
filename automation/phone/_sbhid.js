'use strict';
import ObjC from 'frida-objc-bridge';

rpc.exports = {
  methods: function () {
    const C = ObjC.classes.SBHIDEventDispatchController;
    if (!C) return { err: 'no class' };
    return { own: C.$ownMethods };
  },
};
