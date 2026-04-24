import { initializeApp, getApp, getApps, FirebaseApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider, signInWithPopup, Auth } from 'firebase/auth';
import { getFirestore, doc, getDocFromServer, Firestore } from 'firebase/firestore';

let app: FirebaseApp | null = null;
let auth: Auth | null = null;
let db: Firestore | null = null;

// Use import.meta.env which is standard for Vite
const firebaseConfigEnv = import.meta.env.VITE_FIREBASE_CONFIG;

try {
  let config = null;
  if (firebaseConfigEnv) {
    config = JSON.parse(firebaseConfigEnv);
  }

  if (config) {
    app = !getApps().length ? initializeApp(config) : getApp();
    auth = getAuth(app);
    db = getFirestore(app, config.firestoreDatabaseId);
    console.log("Firebase initialized successfully.");
  }
} catch (e) {
  console.warn("Firebase config missing or invalid. Features disabled.");
}

export { auth, db };

const provider = new GoogleAuthProvider();

export const signIn = async () => {
  if (!auth) {
    console.error("Auth not initialized");
    return null;
  }
  try {
    const result = await signInWithPopup(auth, provider);
    return result.user;
  } catch (error) {
    console.error("Auth Error", error);
    return null;
  }
};

export async function testConnection() {
  if (!db) return;
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
  } catch (error) {
    if(error instanceof Error && error.message.includes('the client is offline')) {
      console.error("Remote connectivity issues.");
    }
  }
}
