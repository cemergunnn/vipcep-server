        // Credit transactions tablosu - düzeltilmiş
        await pool.query(`
            CREATE TABLE IF NOT EXISTS credit_transactions (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(10),
                transaction_type VARCHAR(20),
                amount INTEGER,
                balance_after INTEGER,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Eğer balance_after kolonu yoksa ekle (migration)
        await pool.query(`
            DO $$ 
            BEGIN 
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                    WHERE table_name='credit_transactions' AND column_name='balance_after') 
                THEN 
                    ALTER TABLE credit_transactions ADD COLUMN balance_after INTEGER;
                END IF;
            END $$;
        `);
