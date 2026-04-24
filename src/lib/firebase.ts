import { initializeApp, getApp, getApps, FirebaseApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider, signInWithPopup, Auth } from 'firebase/auth';
import { getFirestore, doc, getDocFromServer, Firestore } from 'firebase/firestore';

let app: FirebaseApp | undefined;
let auth: Auth | undefined;
let db: Firestore | undefined;

// Defensive check for Vite environment variables
const configStr = import.meta.env.VITE_FIREBASE_CONFIG;

if (configStr) {
  try {
    const config = JSON.parse(configStr);
    app = !getApps().length ? initializeApp(config) : getApp();
    auth = getAuth(app);
    db = getFirestore(app, config.firestoreDatabaseId);
    console.log("Firebase initialized.");
  } catch (err) {
    console.warn("Firebase config check bypassed.");
  }
}

export { auth, db };

const provider = new GoogleAuthProvider();

export const signIn = async () => {
  if (!auth) {
    console.warn("Sign-in unavailable: Configuration missing.");
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
    console.error("Connectivity check limited.");
  }
}
