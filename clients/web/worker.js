import init, {
  Session,
  RecipientIdentity,
  generate
} from './wasm/petika_web.js';
import {
  parseOtp,
  totp
} from './otp.js';
let session, identity, accessDraft;
const ready = init();
let queue = Promise.resolve();
self.onmessage = ({
  data
}) => {
  queue = queue.then(async () => {
    const {
      id,
      action,
      args = []
    } = data;
    try {
      await ready;
      let value;
      switch (action) {
        case 'create':
          session?.free();
          session = Session.create(...args);
          break;
        case 'open': {
          const opened = Session.open(new TextEncoder().encode(args[0]), args[1]);
          session?.free();
          session = opened;
          break;
        }
        case 'identity-generate':
          identity?.free(); identity = RecipientIdentity.generate(...args);
          value = JSON.parse(identity.public_identity());
          break;
        case 'identity-open':
          identity?.free(); identity = RecipientIdentity.open(new TextEncoder().encode(args[0]), args[1], args[2]);
          value = JSON.parse(identity.public_identity());
          break;
        case 'identity-seal':
          value = JSON.parse(new TextDecoder().decode(identity.seal(args[0])));
          break;
        case 'identity-verify':
          identity.verify(JSON.stringify(args[0]), args[1]);
          break;
        case 'key-package':
          value = JSON.parse(identity.package(accessDraft || session, JSON.stringify(args[0]), BigInt(args[1])));
          break;
        case 'key-unlock': {
          const opened = identity.unlock(JSON.stringify(args[0]), JSON.stringify(args[1]), new TextEncoder().encode(args[2]), JSON.stringify(args[3]), args[4]);
          session?.free(); session = opened;
          break;
        }
        case 'bind-collection':
          accessDraft?.free(); accessDraft = session.bind_collection(...args);
          break;
        case 'rotate': {
          accessDraft?.free(); accessDraft = session.rotate(args[0]);
          break;
        }
        case 'access-seal':
          value = new TextDecoder().decode(accessDraft.seal());
          break;
        case 'access-commit':
          if (accessDraft) { session?.free(); session = accessDraft; accessDraft = null; }
          break;
        case 'access-abort':
          accessDraft?.free(); accessDraft = null;
          break;
        case 'list':
          value = JSON.parse(session.list());
          break;
        case 'get': {
          value = JSON.parse(session.get(args[0]));
          value.otp = Boolean(value.otp);
          break;
        }
        case 'edit':
          value = JSON.parse(session.get(args[0]));
          break;
        case 'put':
          parseOtp(args[1].otp || '');
          session.put(args[0], JSON.stringify(args[1]), args[2]);
          break;
        case 'remove':
          session.remove(args[0]);
          break;
        case 'seal':
          value = new TextDecoder().decode(session.seal());
          break;
        case 'mode':
          value = session.mode();
          break;
        case 'generate':
          value = generate(args[0]);
          break;
        case 'otp':
          value = await totp(JSON.parse(session.get(args[0])).otp || '');
          break;
        case 'rewrap':
          session.change_passphrase(args[0]);
          break;
        default:
          throw new Error('Unknown operation');
      }
      self.postMessage({
        id,
        value
      });
    } catch (error) {
      self.postMessage({
        id,
        error: String(error.message || error)
      });
    }
  });
};
