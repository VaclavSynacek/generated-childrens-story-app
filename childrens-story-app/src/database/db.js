const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const config = require('../config');

const dbPath = config.databaseUrl.startsWith('file:')
  ? config.databaseUrl.substring(5)
  : config.databaseUrl;

// Ensure the directory exists
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
  console.log(`Created database directory: ${dbDir}`);
}

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
    process.exit(1); // Exit if DB connection fails
  } else {
    console.log(`Connected to the SQLite database at ${dbPath}`);
    // Enable foreign key constraints
    db.exec('PRAGMA foreign_keys = ON;', (execErr) => {
        if(execErr) {
            console.error("Error enabling foreign keys:", execErr.message);
        }
    });
  }
});

// Promise-based wrappers for common operations
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      // Use function() to access 'this' (lastID, changes)
      if (err) {
        console.error('DB Run Error:', err.message, 'SQL:', sql, 'Params:', params);
        reject(err);
      } else {
        resolve({ lastID: this.lastID, changes: this.changes });
      }
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) {
        console.error('DB Get Error:', err.message, 'SQL:', sql, 'Params:', params);
        reject(err);
      } else {
        resolve(row);
      }
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        console.error('DB All Error:', err.message, 'SQL:', sql, 'Params:', params);
        reject(err);
      } else {
        resolve(rows);
      }
    });
  });
}

// Function to initialize the database schema
async function initDb() {
  try {
    const schemaPath = path.join(__dirname, 'schema.sql');
    const schemaSql = fs.readFileSync(schemaPath, 'utf8');
    // Split schema into individual statements to execute sequentially
    const statements = schemaSql.split(';').filter(s => s.trim() !== '');

    console.log('Initializing database schema...');
    // Use serialize to ensure statements run in order
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.exec('BEGIN TRANSACTION;', (beginErr) => { // Wrap in transaction
                if (beginErr) return reject(beginErr);

                statements.forEach((statement, index) => {
                    if (statement.trim()) { // Ensure not empty
                        db.run(statement + ';', (err) => { // Add semicolon back
                            if (err) {
                                // Ignore "already exists" errors for tables/indexes
                                if (!err.message.includes('already exists')) {
                                    console.error(`Schema Error executing: ${statement}\n`, err.message);
                                    db.exec('ROLLBACK;', () => reject(err)); // Rollback on error
                                }
                            }
                            // Check if this is the last statement to commit/resolve
                            if (index === statements.length - 1) {
                                db.exec('COMMIT;', (commitErr) => {
                                    if (commitErr) {
                                        reject(commitErr);
                                    } else {
                                        console.log('Database schema initialization finished successfully.');
                                        resolve();
                                    }
                                });
                            }
                        });
                    } else if (index === statements.length - 1) {
                         // Handle case where last item is empty after split
                         db.exec('COMMIT;', (commitErr) => {
                            if (commitErr) {
                                reject(commitErr);
                            } else {
                                console.log('Database schema initialization finished successfully (last statement empty).');
                                resolve();
                            }
                        });
                    }
                });
            });
        });
    });

  } catch (err) {
    console.error('Failed to initialize database schema:', err);
    throw err; // Re-throw to indicate failure
  }
}

module.exports = {
  db, // Export the raw db instance if needed elsewhere
  run,
  get,
  all,
  initDb,
};
