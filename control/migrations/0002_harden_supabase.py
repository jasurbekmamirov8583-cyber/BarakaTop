from django.db import migrations


def harden(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("""
            DO $$
            DECLARE item record;
            BEGIN
              FOR item IN
                SELECT schemaname, tablename FROM pg_tables
                WHERE schemaname = 'public'
                  AND (tablename LIKE 'control_%' OR tablename LIKE 'auth_%' OR tablename LIKE 'django_%')
              LOOP
                EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM PUBLIC', item.schemaname, item.tablename);
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
                  EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM anon', item.schemaname, item.tablename);
                END IF;
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
                  EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM authenticated', item.schemaname, item.tablename);
                END IF;
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
                  EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM service_role', item.schemaname, item.tablename);
                END IF;
                EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', item.schemaname, item.tablename);
              END LOOP;
              FOR item IN
                SELECT schemaname, sequencename AS tablename FROM pg_sequences
                WHERE schemaname = 'public'
                  AND (sequencename LIKE 'control_%' OR sequencename LIKE 'auth_%' OR sequencename LIKE 'django_%')
              LOOP
                EXECUTE format('REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM PUBLIC', item.schemaname, item.tablename);
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
                  EXECUTE format('REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM anon', item.schemaname, item.tablename);
                END IF;
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
                  EXECUTE format('REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM authenticated', item.schemaname, item.tablename);
                END IF;
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
                  EXECUTE format('REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM service_role', item.schemaname, item.tablename);
                END IF;
              END LOOP;
            END $$;
        """)


class Migration(migrations.Migration):
    dependencies = [("control", "0001_initial"), ("sessions", "0001_initial"), ("admin", "0003_logentry_add_action_flag_choices")]
    operations = [migrations.RunPython(harden, migrations.RunPython.noop)]
