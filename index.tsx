import { GoogleGenAI } from "@google/genai";

let ai: GoogleGenAI | null = null;

// Initialize with default if available, but allow dynamic update
if (process.env.API_KEY) {
    try {
        ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
    } catch (e) {
        console.error("Default Gemini SDK Init Error:", e);
    }
}

/**
 * Helper to strip Markdown code blocks from JSON strings.
 */
function cleanJson(text: string): string {
  if (!text) return "{}";
  // Remove ```json and ``` lines
  let cleaned = text.replace(/^```json\s*/i, "").replace(/^```\s*/, "").replace(/```\s*$/, "");
  return cleaned.trim();
}

/**
 * Helper to call the OpenAI Server Proxy
 */
async function callOpenAI(endpoint: 'chat' | 'audio', data: any): Promise<any> {
    try {
        const res = await fetch('api.php?action=openai_proxy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ endpoint, ...data })
        });
        
        // Check if response is JSON (backend might return HTML on error in dev environments)
        const contentType = res.headers.get("content-type");
        if (!contentType || !contentType.includes("application/json")) {
             console.error("OpenAI Proxy Error: Invalid response from backend");
             return null;
        }

        const json = await res.json();
        if(json.status === 'success') return json.data;
        
        console.error("OpenAI Error:", json.error);
        return null;
    } catch(e) {
        console.error("OpenAI Network Error:", e);
        return null;
    }
}

/**
 * TraKr AI Service
 * Handles all Gemini-related tasks directly in the browser via the official SDK,
 * and OpenAI tasks via server-side proxy for Wallet features.
 */
export const aiService = {
  /**
   * Initialize or update Gemini SDK with a new API Key
   */
  init(apiKey: string) {
      if (!apiKey) return;
      try {
          ai = new GoogleGenAI({ apiKey });
      } catch (error) {
          console.error("Gemini SDK Init Error:", error);
      }
  },

  /**
   * Generates a response using the latest Gemini model.
   * Now accepts an optional language parameter to customize the response.
   */
  async generateContent(prompt: string, language: string = 'English'): Promise<string> {
    if (!ai) return "AI Service Unavailable (Init Failed)";
    try {
      // Append language instruction
      const fullPrompt = `${prompt}\n(Please respond in ${language})`;
      
      const response = await ai.models.generateContent({
        model: 'gemini-3-flash-preview',
        contents: fullPrompt,
        config: {
          temperature: 0.7,
        }
      });
      return response.text || "";
    } catch (error) {
      console.error("Gemini SDK Error:", error);
      return "AI Service Unavailable. Please check your connection or API Key.";
    }
  },

  /**
   * Specialized method for task refinement.
   */
  async polishTask(task: string, language: string = 'English'): Promise<string> {
    const prompt = `You are a productivity expert. Rewrite this task to be clear, professional, and action-oriented (max 10 words): "${task}". Respond in ${language}.`;
    return this.generateContent(prompt, language); // Pass language but handled in prompt string anyway
  },

  /**
   * Processes a natural language command using the TraKr Agent Persona.
   */
  async processAgentCommand(text: string, language: string = 'English'): Promise<any> {
    if (!ai) return null;
    
    const prompt = `
    **System Role:**
    You are TraKr, an AI Resource Manager responsible for optimizing the user's Time (Tasks) and Money (Expenses).
    
    **Language Instruction:**
    The user speaks ${language}. You MUST reply in ${language} for the "voice_reply" field.

    **Your Capabilities:**
    1. Parse & Log: accurately extract amounts, categories, dates, and task details from natural speech.
    2. Coach: If a user spends impulsively or overcommits to tasks, gently warn them.
    3. Contextualize: Recognize patterns (e.g., late-night food orders = "Stressed").

    **Response Format (Strict JSON):**
    You must output a single JSON object. No markdown. No conversational filler.

    {
      "voice_reply": "String. A short, natural, text-to-speech friendly response in ${language} (max 2 sentences).",
      "intent_expense": { 
          "detected": boolean, 
          "amount": number, 
          "currency": "INR", 
          "category": "String", 
          "item": "String" 
      },
      "intent_task": { 
          "detected": boolean, 
          "title": "String", 
          "due_date": "YYYY-MM-DD HH:MM", 
          "priority": "High/Medium/Low" 
      },
      "intent_advice": {
          "detected": boolean,
          "topic": "String (e.g., 'Budget', 'Productivity')"
      }
    }

    **Rules:**
    - If the user says "I bought X", infer the category.
    - If the user implies urgency ("I must do X"), mark priority as High.
    - If the user sounds unsure ("Should I buy this?"), provide advice in 'voice_reply' and set 'detected' to false for expense.

    **User Input:** "${text}"
    `;

    try {
      const response = await ai.models.generateContent({
        model: 'gemini-3-flash-preview',
        contents: prompt,
        config: {
          responseMimeType: "application/json"
        }
      });
      
      const cleanedText = cleanJson(response.text || '{}');
      return JSON.parse(cleanedText);
    } catch (e) {
      console.error("Agent Processing Error:", e);
      return null;
    }
  },

  /**
   * Extracts data from a financial SMS or text snippet.
   * Supports OpenAI via proxy for Wallet page.
   */
  async parseFinanceSnippet(snippet: string, useOpenAI = false): Promise<any> {
    if (useOpenAI) {
        const prompt = `Extract financial transaction data from this text: "${snippet}". 
        Return ONLY a JSON object with: {amount: number, merchant: string, category: string}. 
        Categories: Food, Transport, Shopping, Bills, Health, Entertainment, Other.`;
        
        const data = await callOpenAI('chat', {
            payload: {
                model: "gpt-4o",
                messages: [{ role: "user", content: prompt }],
                response_format: { type: "json_object" }
            }
        });
        
        try {
            const content = data?.choices?.[0]?.message?.content;
            return content ? JSON.parse(content) : null;
        } catch(e) {
            return null;
        }
    }

    if (!ai) return null;
    const prompt = `Extract financial transaction data from this text: "${snippet}". 
    Return ONLY a JSON object with: {amount: number, merchant: string, category: string}. 
    Categories: Food, Transport, Shopping, Bills, Health, Entertainment, Other.`;
    
    try {
      const response = await ai.models.generateContent({
        model: 'gemini-3-flash-preview',
        contents: prompt,
        config: {
          responseMimeType: "application/json"
        }
      });
      
      const cleanedText = cleanJson(response.text || '{}');
      return JSON.parse(cleanedText);
    } catch (e) {
      console.error("Extraction error:", e);
      return null;
    }
  },

  /**
   * Analyzes an image (Receipt Scanning)
   * Supports OpenAI Vision via proxy for Wallet page.
   */
  async analyzeImage(base64Data: string, _promptText: string, useOpenAI = false): Promise<string> {
    const base64 = base64Data.includes(',') ? base64Data.split(',')[1] : base64Data;
    
    const prompt = `Analyze this receipt image and extract the following specific details into a structured JSON object:
    - amount: The total amount paid (number).
    - merchant: The merchant name.
    - date: The transaction date (YYYY-MM-DD).
    - items: An array of line items purchased.
    - category: The best fitting category from [Food, Transport, Shopping, Bills, Health, Entertainment, Other].
    
    Return ONLY valid JSON.`;

    if (useOpenAI) {
        const data = await callOpenAI('chat', {
            payload: {
                model: "gpt-4o",
                messages: [
                    {
                        role: "user",
                        content: [
                            { type: "text", text: prompt },
                            { type: "image_url", image_url: { url: `data:image/jpeg;base64,${base64}` } }
                        ]
                    }
                ],
                response_format: { type: "json_object" }
            }
        });
        const txt = data?.choices?.[0]?.message?.content || "{}";
        return cleanJson(txt);
    }

    if (!ai) return "{}";
    try {
      const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash-image',
          contents: {
              parts: [
                  { inlineData: { mimeType: 'image/jpeg', data: base64 } },
                  { text: prompt }
              ]
          }
          // Note: responseMimeType is not supported for gemini-2.5-flash-image
      });
      const cleanedText = cleanJson(response.text || "{}");
      return cleanedText;
    } catch (e) {
        console.error("Vision Error:", e);
        return "{}";
    }
  },

  /**
   * Transcribes audio (Voice Input)
   * Supports OpenAI Whisper via proxy for Wallet page.
   */
  async transcribeAudio(audioBlob: Blob, useOpenAI = false): Promise<string> {
    if (useOpenAI) {
        // Convert Blob to Base64 to send to PHP Proxy
        try {
            const base64 = await new Promise<string>((resolve) => {
                const reader = new FileReader();
                reader.onloadend = () => resolve(reader.result as string);
                reader.readAsDataURL(audioBlob);
            });
            const dataStr = base64.split(',')[1];
            
            const data = await callOpenAI('audio', { audio: dataStr });
            return data?.text || "";
        } catch(e) {
            console.error("OpenAI Audio Error", e);
            return "";
        }
    }

    if (!ai) return "";
    try {
        const base64 = await new Promise<string>((resolve) => {
            const reader = new FileReader();
            reader.onloadend = () => resolve(reader.result as string);
            reader.readAsDataURL(audioBlob);
        });
        const data = base64.split(',')[1];

        const response = await ai.models.generateContent({
            model: 'gemini-2.0-flash',
            contents: {
                parts: [
                    { inlineData: { mimeType: 'audio/webm', data: data } },
                    { text: "Transcribe this audio exactly as spoken. Do not add any commentary." }
                ]
            }
        });
        return response.text || "";
    } catch (e) {
        console.error("Transcription Error:", e);
        return "";
    }
  }
};

// Expose to window for Alpine.js integration
(window as any).aiService = aiService;