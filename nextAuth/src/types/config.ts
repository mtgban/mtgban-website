export interface ConfigType {
    port: string;
    datastore_path: string;
    game: string;
    db_address: string;
    redis_addr: string;
    discord_hook: string;
    discord_notif_hook: string;
    discord_invite_link: string;
    affiliate: { [key: string]: string };
    affiliates_list: string[];
    affiliates_buylist_list: string[];
    api: { [key: string]: string };
    api_demo_stores: string[];
    discord_token: string;
    discord_allowlist: string[];
    arbit_default_sellers: string[];
    arbit_block_vendors: string[];
    search_block_list: string[];
    search_buylist_block_list: string[];
    sleepers_block_list: string[];
    global_allow_list: string[];
    global_probe_list: string[];
    patreon: {
        secret: { [key: string]: string };
        grants: {
            category: string;
            email: string;
            name: string;
            tier: string;
        }[];
    };
    api_user_secrets: { [key: string]: string };
    google_credentials: string;
    db: {
        log_prefix: string;
        supabase_anon_key: string;
        role_key: string;
        supabase_jwt_secret: string;
        supabase_url: string;
    };
    acl: {
        roles: { [key: string]: { [key: string]: { [key: string]: string } } };
        tiers: { [key: string]: { [key: string]: { [key: string]: string } } };
    };
    session_file: string;
    uploader: {
        moxfield: string;
    };
    slow_start: boolean;
}