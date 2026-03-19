import Foundation

/// A utility class responsible for padding messages to fixed bucket sizes.
/// This helps prevent traffic analysis by obscuring the actual length of messages.
class Padder {
    /// The fixed bucket size for messages (512 bytes).
    private static let bucketSize = 512

    /// Pads the given message data to the nearest multiple of the bucket size.
    ///
    /// - Parameter message: The original message data.
    /// - Returns: The padded data, with a size that is a multiple of 512 bytes.
    static func pad(message: Data) -> Data {
        let length = message.count
        
        // If the message is empty, we pad it to one full bucket.
        if length == 0 {
            return Data(repeating: 0, count: bucketSize)
        }
        
        let remainder = length % bucketSize
        
        // If the message is already a multiple of the bucket size, return it as is.
        if remainder == 0 {
            return message
        }
        
        // Calculate how many bytes of padding are needed to reach the next bucket size.
        let paddingNeeded = bucketSize - remainder
        
        var paddedMessage = message
        // Append zero bytes as padding.
        paddedMessage.append(Data(repeating: 0, count: paddingNeeded))
        
        return paddedMessage
    }
}