import Foundation

protocol ReconModule {
    var name: String { get }
    var timeout: TimeInterval { get }
    func run(engine: ReconEngine)
}

extension ReconModule {
    var timeout: TimeInterval { 60 }
}
