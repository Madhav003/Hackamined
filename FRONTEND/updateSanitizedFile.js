/**
 * updateSanitizedFile.js
 * 
 * Standalone utility to update a file's sanitized version in Firestore.
 * Uses Firestore-only approach (no Firebase Storage needed).
 * 
 * Usage:
 *   1. Call updateSanitizedFile(fileDocId) to mark a file as completed
 *   2. Call setFileProcessing(fileDocId) to mark a file as processing
 */

/**
 * Marks a Firestore file document as "completed" (sanitized).
 * @param {string} fileDocId - The Firestore document ID from the 'files' collection.
 */
async function updateSanitizedFile(fileDocId) {
    try {
        await window.updateDoc(window.doc(window.firebaseDb, 'files', fileDocId), {
            status: 'completed'
        });
        console.log(`File ${fileDocId} marked as completed.`);
    } catch (error) {
        console.error('Error updating file:', error);
        throw error;
    }
}

/**
 * Sets file status to "processing" (useful before starting sanitization).
 * @param {string} fileDocId - The Firestore document ID from the 'files' collection.
 */
async function setFileProcessing(fileDocId) {
    try {
        await window.updateDoc(window.doc(window.firebaseDb, 'files', fileDocId), {
            status: 'processing'
        });
        console.log(`File ${fileDocId} status set to processing.`);
    } catch (error) {
        console.error('Error setting file to processing:', error);
        throw error;
    }
}

// Expose globally
window.updateSanitizedFile = updateSanitizedFile;
window.setFileProcessing = setFileProcessing;
