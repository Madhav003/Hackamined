// 1. Import Firebase Core and the specifically needed services
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.9.0/firebase-app.js";
import {
  getAuth,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  onAuthStateChanged,
  signOut
} from "https://www.gstatic.com/firebasejs/10.9.0/firebase-auth.js";
import {
  getFirestore,
  doc,
  setDoc,
  getDoc,
  collection,
  addDoc,
  getDocs,
  query,
  where,
  updateDoc,
  deleteDoc,
  orderBy,
  limit,
  onSnapshot,
  serverTimestamp,
  Timestamp
} from "https://www.gstatic.com/firebasejs/10.9.0/firebase-firestore.js";
import {
  getStorage,
  ref,
  uploadBytes,
  uploadBytesResumable,
  getDownloadURL
} from "https://www.gstatic.com/firebasejs/10.9.0/firebase-storage.js";

// 2. Initialize Firebase (REPLACE these values with YOUR actual config from the Firebase Console)
const firebaseConfig = {
  apiKey: "AIzaSyD3Co2otMbxCeMtRJWdPcIiVPa_F3ZlFbI",
  authDomain: "pii-sanitizer.firebaseapp.com",
  projectId: "pii-sanitizer",
  storageBucket: "pii-sanitizer.firebasestorage.app",
  messagingSenderId: "994825264815",
  appId: "1:994825264815:web:58d44a056c3530ca5efe5a"
};

// Initialize App, Auth, and Firestore
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);
const storage = getStorage(app);

// 3. Expose them globally so they can be accessed by scripts, 
// including React components transpiled by Babel running in the browser.
window.firebaseAuth = auth;
window.firebaseDb = db;
window.firebaseStorage = storage;
window.createUserWithEmailAndPassword = createUserWithEmailAndPassword;
window.signInWithEmailAndPassword = signInWithEmailAndPassword;
window.doc = doc;
window.setDoc = setDoc;
window.getDoc = getDoc;
window.collection = collection;
window.addDoc = addDoc;
window.getDocs = getDocs;
window.query = query;
window.where = where;
window.updateDoc = updateDoc;
window.deleteDoc = deleteDoc;
window.orderBy = orderBy;
window.limit = limit;
window.onSnapshot = onSnapshot;
window.serverTimestamp = serverTimestamp;
window.Timestamp = Timestamp;
window.ref = ref;
window.uploadBytes = uploadBytes;
window.uploadBytesResumable = uploadBytesResumable;
window.getDownloadURL = getDownloadURL;
window.onAuthStateChanged = onAuthStateChanged;
window.signOut = signOut;

console.log("Firebase initialized successfully.");
