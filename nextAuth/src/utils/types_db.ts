export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  public: {
    Tables: {
      active_subscribers: {
        Row: {
          current_period_end: string | null
          email: string | null
          features: Json | null
          status: string | null
          stripe_customer_id: string | null
          tier: string | null
          uuid: string | null
        }
        Insert: {
          current_period_end?: string | null
          email?: string | null
          features?: Json | null
          status?: string | null
          stripe_customer_id?: string | null
          tier?: string | null
          uuid?: string | null
        }
        Update: {
          current_period_end?: string | null
          email?: string | null
          features?: Json | null
          status?: string | null
          stripe_customer_id?: string | null
          tier?: string | null
          uuid?: string | null
        }
        Relationships: []
      }
      api_responses: {
        Row: {
          created_at: string | null
          headers: Json | null
          id: string
          response_body: Json | null
          status_code: number | null
        }
        Insert: {
          created_at?: string | null
          headers?: Json | null
          id?: string
          response_body?: Json | null
          status_code?: number | null
        }
        Update: {
          created_at?: string | null
          headers?: Json | null
          id?: string
          response_body?: Json | null
          status_code?: number | null
        }
        Relationships: []
      }
      auth_events: {
        Row: {
          created_at: string | null
          event_type: string
          id: string
          ip_address: string | null
          user_agent: string | null
          user_id: string | null
        }
        Insert: {
          created_at?: string | null
          event_type: string
          id?: string
          ip_address?: string | null
          user_agent?: string | null
          user_id?: string | null
        }
        Update: {
          created_at?: string | null
          event_type?: string
          id?: string
          ip_address?: string | null
          user_agent?: string | null
          user_id?: string | null
        }
        Relationships: []
      }
      ban_features: {
        Row: {
          default_access: boolean | null
          description: string | null
          page_name: string
        }
        Insert: {
          default_access?: boolean | null
          description?: string | null
          page_name: string
        }
        Update: {
          default_access?: boolean | null
          description?: string | null
          page_name?: string
        }
        Relationships: []
      }
      ban_roles: {
        Row: {
          description: string | null
          is_admin: boolean | null
          role_name: string
        }
        Insert: {
          description?: string | null
          is_admin?: boolean | null
          role_name: string
        }
        Update: {
          description?: string | null
          is_admin?: boolean | null
          role_name?: string
        }
        Relationships: []
      }
      customers: {
        Row: {
          id: string
          stripe_customer_id: string | null
        }
        Insert: {
          id: string
          stripe_customer_id?: string | null
        }
        Update: {
          id?: string
          stripe_customer_id?: string | null
        }
        Relationships: []
      }
      feature_flag_changes: {
        Row: {
          changed_at: string | null
          changed_by: string | null
          feature_category: string
          feature_set: string
          flag_name: string
          id: string
          new_value: string
          old_value: string | null
          user_id: string | null
        }
        Insert: {
          changed_at?: string | null
          changed_by?: string | null
          feature_category: string
          feature_set: string
          flag_name: string
          id?: string
          new_value: string
          old_value?: string | null
          user_id?: string | null
        }
        Update: {
          changed_at?: string | null
          changed_by?: string | null
          feature_category?: string
          feature_set?: string
          flag_name?: string
          id?: string
          new_value?: string
          old_value?: string | null
          user_id?: string | null
        }
        Relationships: []
      }
      feature_flags: {
        Row: {
          data_type: string | null
          default_value: string | null
          description: string | null
          flag_name: string
        }
        Insert: {
          data_type?: string | null
          default_value?: string | null
          description?: string | null
          flag_name: string
        }
        Update: {
          data_type?: string | null
          default_value?: string | null
          description?: string | null
          flag_name?: string
        }
        Relationships: []
      }
      permission_categories: {
        Row: {
          created_at: string | null
          id: number
          name: string
        }
        Insert: {
          created_at?: string | null
          id?: number
          name: string
        }
        Update: {
          created_at?: string | null
          id?: number
          name?: string
        }
        Relationships: []
      }
      permissions: {
        Row: {
          category_id: number | null
          created_at: string | null
          id: number
          permission_key: string
          permission_value: string
          role_id: number | null
        }
        Insert: {
          category_id?: number | null
          created_at?: string | null
          id?: number
          permission_key: string
          permission_value: string
          role_id?: number | null
        }
        Update: {
          category_id?: number | null
          created_at?: string | null
          id?: number
          permission_key?: string
          permission_value?: string
          role_id?: number | null
        }
        Relationships: [
          {
            foreignKeyName: "permissions_category_id_fkey"
            columns: ["category_id"]
            isOneToOne: false
            referencedRelation: "permission_categories"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "permissions_role_id_fkey"
            columns: ["role_id"]
            isOneToOne: false
            referencedRelation: "roles"
            referencedColumns: ["id"]
          },
        ]
      }
      prices: {
        Row: {
          active: boolean | null
          currency: string | null
          description: string | null
          id: string
          interval: Database["public"]["Enums"]["pricing_plan_interval"] | null
          interval_count: number | null
          metadata: Json | null
          product_id: string | null
          trial_period_days: number | null
          type: Database["public"]["Enums"]["pricing_type"] | null
          unit_amount: number | null
        }
        Insert: {
          active?: boolean | null
          currency?: string | null
          description?: string | null
          id: string
          interval?: Database["public"]["Enums"]["pricing_plan_interval"] | null
          interval_count?: number | null
          metadata?: Json | null
          product_id?: string | null
          trial_period_days?: number | null
          type?: Database["public"]["Enums"]["pricing_type"] | null
          unit_amount?: number | null
        }
        Update: {
          active?: boolean | null
          currency?: string | null
          description?: string | null
          id?: string
          interval?: Database["public"]["Enums"]["pricing_plan_interval"] | null
          interval_count?: number | null
          metadata?: Json | null
          product_id?: string | null
          trial_period_days?: number | null
          type?: Database["public"]["Enums"]["pricing_type"] | null
          unit_amount?: number | null
        }
        Relationships: [
          {
            foreignKeyName: "prices_product_id_fkey"
            columns: ["product_id"]
            isOneToOne: false
            referencedRelation: "products"
            referencedColumns: ["id"]
          },
        ]
      }
      products: {
        Row: {
          active: boolean | null
          description: string | null
          id: string
          image: string | null
          metadata: Json | null
          name: string | null
        }
        Insert: {
          active?: boolean | null
          description?: string | null
          id: string
          image?: string | null
          metadata?: Json | null
          name?: string | null
        }
        Update: {
          active?: boolean | null
          description?: string | null
          id?: string
          image?: string | null
          metadata?: Json | null
          name?: string | null
        }
        Relationships: []
      }
      role_changes: {
        Row: {
          changed_at: string | null
          changed_by: string | null
          id: string
          new_role: string
          old_role: string | null
          user_id: string | null
        }
        Insert: {
          changed_at?: string | null
          changed_by?: string | null
          id?: string
          new_role: string
          old_role?: string | null
          user_id?: string | null
        }
        Update: {
          changed_at?: string | null
          changed_by?: string | null
          id?: string
          new_role?: string
          old_role?: string | null
          user_id?: string | null
        }
        Relationships: []
      }
      role_page_access: {
        Row: {
          page_name: string
          role_name: string
        }
        Insert: {
          page_name: string
          role_name: string
        }
        Update: {
          page_name?: string
          role_name?: string
        }
        Relationships: [
          {
            foreignKeyName: "role_page_access_page_name_fkey"
            columns: ["page_name"]
            isOneToOne: false
            referencedRelation: "ban_features"
            referencedColumns: ["page_name"]
          },
          {
            foreignKeyName: "role_page_access_role_name_fkey"
            columns: ["role_name"]
            isOneToOne: false
            referencedRelation: "ban_roles"
            referencedColumns: ["role_name"]
          },
        ]
      }
      roles: {
        Row: {
          created_at: string | null
          id: number
          name: string
          permissions: Json
        }
        Insert: {
          created_at?: string | null
          id?: number
          name: string
          permissions: Json
        }
        Update: {
          created_at?: string | null
          id?: number
          name?: string
          permissions?: Json
        }
        Relationships: []
      }
      session_metadata: {
        Row: {
          device_info: Json | null
          ip_address: string | null
          last_active_at: string | null
          session_id: string
          user_agent: string | null
          user_id: string | null
        }
        Insert: {
          device_info?: Json | null
          ip_address?: string | null
          last_active_at?: string | null
          session_id: string
          user_agent?: string | null
          user_id?: string | null
        }
        Update: {
          device_info?: Json | null
          ip_address?: string | null
          last_active_at?: string | null
          session_id?: string
          user_agent?: string | null
          user_id?: string | null
        }
        Relationships: []
      }
      sub_tiers: {
        Row: {
          description: string | null
          is_premium: boolean | null
          tier_name: string
          tier_order: number
        }
        Insert: {
          description?: string | null
          is_premium?: boolean | null
          tier_name: string
          tier_order: number
        }
        Update: {
          description?: string | null
          is_premium?: boolean | null
          tier_name?: string
          tier_order?: number
        }
        Relationships: []
      }
      subscription_history: {
        Row: {
          changed_at: string | null
          id: string
          new_status: string
          new_tier: string
          old_status: string | null
          old_tier: string | null
          user_id: string | null
        }
        Insert: {
          changed_at?: string | null
          id?: string
          new_status: string
          new_tier: string
          old_status?: string | null
          old_tier?: string | null
          user_id?: string | null
        }
        Update: {
          changed_at?: string | null
          id?: string
          new_status?: string
          new_tier?: string
          old_status?: string | null
          old_tier?: string | null
          user_id?: string | null
        }
        Relationships: []
      }
      subscriptions: {
        Row: {
          cancel_at: string | null
          cancel_at_period_end: boolean | null
          canceled_at: string | null
          created: string
          current_period_end: string
          current_period_start: string
          ended_at: string | null
          id: string
          metadata: Json | null
          price_id: string | null
          quantity: number | null
          status: Database["public"]["Enums"]["subscription_status"] | null
          trial_end: string | null
          trial_start: string | null
          user_id: string
        }
        Insert: {
          cancel_at?: string | null
          cancel_at_period_end?: boolean | null
          canceled_at?: string | null
          created?: string
          current_period_end?: string
          current_period_start?: string
          ended_at?: string | null
          id: string
          metadata?: Json | null
          price_id?: string | null
          quantity?: number | null
          status?: Database["public"]["Enums"]["subscription_status"] | null
          trial_end?: string | null
          trial_start?: string | null
          user_id: string
        }
        Update: {
          cancel_at?: string | null
          cancel_at_period_end?: boolean | null
          canceled_at?: string | null
          created?: string
          current_period_end?: string
          current_period_start?: string
          ended_at?: string | null
          id?: string
          metadata?: Json | null
          price_id?: string | null
          quantity?: number | null
          status?: Database["public"]["Enums"]["subscription_status"] | null
          trial_end?: string | null
          trial_start?: string | null
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "subscriptions_price_id_fkey"
            columns: ["price_id"]
            isOneToOne: false
            referencedRelation: "prices"
            referencedColumns: ["id"]
          },
        ]
      }
      tier_feature_flags: {
        Row: {
          flag_name: string
          flag_value: string
          tier_name: string
        }
        Insert: {
          flag_name: string
          flag_value: string
          tier_name: string
        }
        Update: {
          flag_name?: string
          flag_value?: string
          tier_name?: string
        }
        Relationships: [
          {
            foreignKeyName: "tier_feature_flags_flag_name_fkey"
            columns: ["flag_name"]
            isOneToOne: false
            referencedRelation: "feature_flags"
            referencedColumns: ["flag_name"]
          },
          {
            foreignKeyName: "tier_feature_flags_tier_name_fkey"
            columns: ["tier_name"]
            isOneToOne: false
            referencedRelation: "sub_tiers"
            referencedColumns: ["tier_name"]
          },
          {
            foreignKeyName: "tier_feature_flags_tier_name_fkey"
            columns: ["tier_name"]
            isOneToOne: false
            referencedRelation: "tier_access"
            referencedColumns: ["tier_name"]
          },
        ]
      }
      tier_page_access: {
        Row: {
          page_name: string
          tier_name: string
        }
        Insert: {
          page_name: string
          tier_name: string
        }
        Update: {
          page_name?: string
          tier_name?: string
        }
        Relationships: [
          {
            foreignKeyName: "tier_page_access_page_name_fkey"
            columns: ["page_name"]
            isOneToOne: false
            referencedRelation: "ban_features"
            referencedColumns: ["page_name"]
          },
          {
            foreignKeyName: "tier_page_access_tier_name_fkey"
            columns: ["tier_name"]
            isOneToOne: false
            referencedRelation: "sub_tiers"
            referencedColumns: ["tier_name"]
          },
          {
            foreignKeyName: "tier_page_access_tier_name_fkey"
            columns: ["tier_name"]
            isOneToOne: false
            referencedRelation: "tier_access"
            referencedColumns: ["tier_name"]
          },
        ]
      }
      tiers: {
        Row: {
          id: number
          name: string | null
          tier_id: string
        }
        Insert: {
          id?: number
          name?: string | null
          tier_id: string
        }
        Update: {
          id?: number
          name?: string | null
          tier_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "fk_tier_id"
            columns: ["tier_id"]
            isOneToOne: false
            referencedRelation: "products"
            referencedColumns: ["id"]
          },
        ]
      }
      user_permissions: {
        Row: {
          created_at: string | null
          email: string
          features: Json | null
          id: string
          role: string
          status: string
          tier: string
          updated_at: string | null
        }
        Insert: {
          created_at?: string | null
          email: string
          features?: Json | null
          id: string
          role?: string
          status?: string
          tier?: string
          updated_at?: string | null
        }
        Update: {
          created_at?: string | null
          email?: string
          features?: Json | null
          id?: string
          role?: string
          status?: string
          tier?: string
          updated_at?: string | null
        }
        Relationships: []
      }
      user_roles: {
        Row: {
          created_at: string | null
          id: number
          role_id: number | null
          user_id: string | null
        }
        Insert: {
          created_at?: string | null
          id?: number
          role_id?: number | null
          user_id?: string | null
        }
        Update: {
          created_at?: string | null
          id?: number
          role_id?: number | null
          user_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "user_roles_role_id_fkey"
            columns: ["role_id"]
            isOneToOne: false
            referencedRelation: "roles"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "user_roles_user_id_fkey"
            columns: ["user_id"]
            isOneToOne: false
            referencedRelation: "users"
            referencedColumns: ["id"]
          },
        ]
      }
      users: {
        Row: {
          billing_address: Json | null
          email: string | null
          full_name: string | null
          id: string
          payment_method: Json | null
          permissions: Json | null
          preferences: Json | null
        }
        Insert: {
          billing_address?: Json | null
          email?: string | null
          full_name?: string | null
          id: string
          payment_method?: Json | null
          permissions?: Json | null
          preferences?: Json | null
        }
        Update: {
          billing_address?: Json | null
          email?: string | null
          full_name?: string | null
          id?: string
          payment_method?: Json | null
          permissions?: Json | null
          preferences?: Json | null
        }
        Relationships: []
      }
    }
    Views: {
      tcg_price_trend: {
        Row: {
          captured_at: string | null
          high_price: number | null
          low_price: number | null
          market_price: number | null
          price_date: string | null
          quantity_sold: number | null
          response_id: string | null
          sku_id: string | null
          transaction_count: number | null
        }
        Relationships: []
      }
      tier_access: {
        Row: {
          features: Json | null
          tier_name: string | null
        }
        Insert: {
          features?: never
          tier_name?: string | null
        }
        Update: {
          features?: never
          tier_name?: string | null
        }
        Relationships: []
      }
    }
    Functions: {
      cleanup_webhook_logs: {
        Args: Record<PropertyKey, never>
        Returns: undefined
      }
      copy_user_permissions: {
        Args: {
          source_user_id: string
          target_user_id: string
        }
        Returns: undefined
      }
      fetch_tcg_price_history: {
        Args: {
          sku_id: string
        }
        Returns: string
      }
      generate_features_for_user: {
        Args: {
          user_id: string
        }
        Returns: Json
      }
      generate_user_token: {
        Args: {
          user_id_param: string
        }
        Returns: string
      }
      get_permission_rpc: {
        Args: {
          user_id_param: string
        }
        Returns: Json
      }
      get_user_active_sessions: {
        Args: {
          p_user_id: string
        }
        Returns: {
          session_id: string
          created_at: string
          last_active_at: string
          expires_at: string
          ip_address: string
          user_agent: string
          device_info: Json
        }[]
      }
      get_user_permissions: {
        Args: {
          "": string
        }
        Returns: string[]
      }
      get_user_with_session: {
        Args: {
          p_session_id: string
        }
        Returns: {
          user_id: string
          email: string
          role: string
          tier: string
          features: Json
          is_valid: boolean
        }[]
      }
      get_users_with_feature: {
        Args: {
          feature_category: string
          feature_set: string
          flag_name: string
          flag_value?: string
        }
        Returns: {
          id: string
          email: string
          role: string
          tier: string
        }[]
      }
      handle_jwt_claims: {
        Args: {
          jwt: Json
        }
        Returns: Json
      }
      handle_stripe_event: {
        Args: {
          subscription_id: string
          customer_id: string
          status: string
          product_id: string
          product_tier: string
        }
        Returns: undefined
      }
      log_auth_event: {
        Args: {
          user_id: string
          event_type: string
          ip_address?: string
          user_agent?: string
        }
        Returns: undefined
      }
      manual_sync_active_subscribers: {
        Args: Record<PropertyKey, never>
        Returns: undefined
      }
      revoke_other_sessions: {
        Args: {
          p_user_id: string
          p_current_session_id: string
        }
        Returns: number
      }
      sync_active_stripe_products: {
        Args: Record<PropertyKey, never>
        Returns: undefined
      }
      sync_all_user_roles: {
        Args: Record<PropertyKey, never>
        Returns: undefined
      }
      sync_related_stripe_prices: {
        Args: Record<PropertyKey, never>
        Returns: undefined
      }
      sync_stripe_state: {
        Args: {
          p_customer_data: Json
          p_subscription_data: Json
        }
        Returns: Json
      }
      sync_user_roles: {
        Args: {
          user_uuid: string
        }
        Returns: undefined
      }
      tcg_last_sold: {
        Args: {
          product_id: string
        }
        Returns: string
      }
      tcg_last_sold2: {
        Args: {
          product_id: string
        }
        Returns: string
      }
      update_all_user_permissions: {
        Args: Record<PropertyKey, never>
        Returns: undefined
      }
      update_feature_flag: {
        Args: {
          user_id: string
          feature_category: string
          feature_set: string
          flag_name: string
          flag_value: string
        }
        Returns: undefined
      }
      update_session_activity: {
        Args: {
          p_session_id: string
          p_ip_address?: string
          p_user_agent?: string
        }
        Returns: boolean
      }
      update_tier_from_subscription: {
        Args: {
          user_id: string
          subscription_tier: string
          subscription_status: string
        }
        Returns: undefined
      }
      update_user_permissions: {
        Args: {
          user_id_param: string
        }
        Returns: Json
      }
      user_has_access: {
        Args: {
          user_id: string
          page_name: string
        }
        Returns: boolean
      }
    }
    Enums: {
      period: "month" | "quarter" | "semi-annual" | "annual"
      pricing_plan_interval: "day" | "week" | "month" | "year"
      pricing_type: "one_time" | "recurring"
      subscription_status:
        | "trialing"
        | "active"
        | "canceled"
        | "incomplete"
        | "incomplete_expired"
        | "past_due"
        | "unpaid"
        | "paused"
      webhook_operation: "INSERT" | "UPDATE" | "DELETE"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type PublicSchema = Database[Extract<keyof Database, "public">]

export type Tables<
  PublicTableNameOrOptions extends
    | keyof (PublicSchema["Tables"] & PublicSchema["Views"])
    | { schema: keyof Database },
  TableName extends PublicTableNameOrOptions extends { schema: keyof Database }
    ? keyof (Database[PublicTableNameOrOptions["schema"]]["Tables"] &
        Database[PublicTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = PublicTableNameOrOptions extends { schema: keyof Database }
  ? (Database[PublicTableNameOrOptions["schema"]]["Tables"] &
      Database[PublicTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : PublicTableNameOrOptions extends keyof (PublicSchema["Tables"] &
        PublicSchema["Views"])
    ? (PublicSchema["Tables"] &
        PublicSchema["Views"])[PublicTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  PublicTableNameOrOptions extends
    | keyof PublicSchema["Tables"]
    | { schema: keyof Database },
  TableName extends PublicTableNameOrOptions extends { schema: keyof Database }
    ? keyof Database[PublicTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = PublicTableNameOrOptions extends { schema: keyof Database }
  ? Database[PublicTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : PublicTableNameOrOptions extends keyof PublicSchema["Tables"]
    ? PublicSchema["Tables"][PublicTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  PublicTableNameOrOptions extends
    | keyof PublicSchema["Tables"]
    | { schema: keyof Database },
  TableName extends PublicTableNameOrOptions extends { schema: keyof Database }
    ? keyof Database[PublicTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = PublicTableNameOrOptions extends { schema: keyof Database }
  ? Database[PublicTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : PublicTableNameOrOptions extends keyof PublicSchema["Tables"]
    ? PublicSchema["Tables"][PublicTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  PublicEnumNameOrOptions extends
    | keyof PublicSchema["Enums"]
    | { schema: keyof Database },
  EnumName extends PublicEnumNameOrOptions extends { schema: keyof Database }
    ? keyof Database[PublicEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = PublicEnumNameOrOptions extends { schema: keyof Database }
  ? Database[PublicEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : PublicEnumNameOrOptions extends keyof PublicSchema["Enums"]
    ? PublicSchema["Enums"][PublicEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof PublicSchema["CompositeTypes"]
    | { schema: keyof Database },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof Database
  }
    ? keyof Database[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends { schema: keyof Database }
  ? Database[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof PublicSchema["CompositeTypes"]
    ? PublicSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never
