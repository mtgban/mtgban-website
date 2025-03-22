'use server';

import { createClient } from '@/utils/supabase/server';
import { revalidatePath } from 'next/cache';

export async function updateUserPreferences(userId: string, data: any) {
  const supabase = createClient();
  
  // Check if user has preferences record
  const { data: existingPrefs } = await supabase
    .from('user_preferences')
    .select('*')
    .eq('id', userId)
    .maybeSingle();
  
  let result;
  
  if (existingPrefs) {
    // Update existing preferences
    result = await supabase
      .from('user_preferences')
      .update(data)
      .eq('id', userId);
  } else {
    // Insert new preferences with user ID
    result = await supabase
      .from('user_preferences')
      .insert({
        id: userId,
        ...data
      });
  }
  
  if (result.error) {
    console.error('Error updating preferences:', result.error);
    throw new Error(result.error.message);
  }
  
  // Revalidate the account page to show updated preferences
  revalidatePath('/account');
  
  return { success: true };
}